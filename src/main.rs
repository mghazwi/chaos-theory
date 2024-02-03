use ark_bls12_381::{g2::Config, Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    pairing::{Pairing, PairingOutput},
    CurveGroup, Group,
};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::Sha256;
use std::{fs::File, io::Read, ops::Mul};
use std::collections::HashMap;

use prompt::{puzzle, welcome};

#[derive(Debug)]
pub enum Error {
    InvalidMsg,
}

fn hasher() -> MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>> {
    let wb_to_curve_hasher =
        MapToCurveBasedHasher::<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<Config>>::new(
            &[1, 3, 3, 7],
        )
        .unwrap();
    wb_to_curve_hasher
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct ElGamal(G1Affine, G1Affine);

impl ElGamal {
    pub fn hash_to_curve(&self) -> G2Affine {
        let mut data = Vec::new();
        self.serialize_uncompressed(&mut data).unwrap();

        hasher().hash(&data).unwrap()
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Message(G1Affine);

struct Sender {
    pub sk: Fr,
    pub pk: G1Affine,
}

pub struct Receiver {
    pk: G1Affine,
}

pub struct Auditor {}

impl Sender {
    pub fn send(&self, m: Message, r: &Receiver) -> ElGamal {
        let c_2: G1Affine = (r.pk.mul(&self.sk) + m.0).into_affine();
        ElGamal(self.pk, c_2)
    }

    pub fn authenticate(&self, c: &ElGamal) -> G2Affine {
        let hash_c = c.hash_to_curve();
        hash_c.mul(&self.sk).into_affine()
    }
}

impl Auditor {
    pub fn check_auth(sender_pk: G1Affine, c: &ElGamal, s: G2Affine) -> bool {
        let lhs = { Bls12_381::pairing(G1Projective::generator(), s) };

        let hash_c = c.hash_to_curve();
        let rhs = { Bls12_381::pairing(sender_pk, hash_c) };

        lhs == rhs
    }
}

#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Blob {
    pub sender_pk: G1Affine,
    pub c: ElGamal,
    pub s: G2Affine,
    pub rec_pk: G1Affine,
}

fn generate_message_space() -> [Message; 10] {
    let g1 = G1Projective::generator();
    let msgs = [
        390183091831u64,
        4987238947234982,
        84327489279482,
        8492374892742,
        5894274824234,
        4982748927426,
        48248927348927427,
        489274982749828,
        99084321987189371,
        8427489729843712893,
    ];
    msgs.iter()
        .map(|&msg_i| Message(g1.mul(Fr::from(msg_i)).into_affine()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

pub fn baby_giant(max_bitwidth: u64, a: &PairingOutput<Bls12_381>, b: &PairingOutput<Bls12_381>) -> u64 {
    let m = 1u64 << (max_bitwidth / 2);

    let mut table = HashMap::new();
    for j in 0u64..m {
        let v = a.mul(Fr::from(j));//.into_affine();
        table.insert(v, j);
    }
    let am = a.mul(Fr::from(m));//.into_affine();
    let mut gamma = b.clone();

    for i in 0u64..m {
        if let Some(j) = table.get(&gamma) {
            return i*m + j;
        }
        gamma = gamma - &am;//.into_affine();
    }

    panic!("No discrete log found");
}

pub fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);

    let messages = generate_message_space();

    let mut file = File::open("blob.bin").unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    let blob = Blob::deserialize_uncompressed(data.as_slice()).unwrap();

    // ensure that blob is correct
    assert!(Auditor::check_auth(blob.sender_pk, &blob.c, blob.s));

    /* Implement your attack here, to find the index of the encrypted message */

    // unimplemented!();
    let g1 = G1Projective::generator();
    let divs = { Bls12_381::pairing(blob.rec_pk, blob.s) };

    let hash_c = blob.c.hash_to_curve();
    let ups = { Bls12_381::pairing(blob.c.1, hash_c) };

    let paired_msg = ups-divs;
    // let pmsg = { Bls12_381::multi_pairing(blob.c.1, hash_c, blob.rec_pk, blob.s) };
    // println!("paired msg: {}", paired_msg);

    let sk = Fr::from(8718712u64);
    let pk = g1.mul(sk).into_affine();

    let s =  Sender { sk,pk};

    let sk2 =  Fr::from(87183453u64);
    let pk2 = g1.mul(sk2).into_affine();

    let r = Receiver{pk:pk2};

    let c = s.send(messages[0], &r);
    let ch = c.hash_to_curve();

    let a = s.authenticate(&c);

    let u1 = { Bls12_381::pairing(c.1, ch) };

    let d1 = { Bls12_381::pairing(pk2, a) };

    let mpp = u1-d1;

    let a = { Bls12_381::pairing(g1, ch) };

    let plain_back = baby_giant(64, &a, &mpp);

    println!("plain back: {}", plain_back);

    let pmi = { Bls12_381::pairing(messages[0].0, ch) };

    if mpp == pmi {
        println!("match")
    }


    for msg in messages {
        let pmi = { Bls12_381::pairing(msg.0, hash_c) };
        if paired_msg == pmi {
            println!("msg found = {}", msg.0);
        }
    }
    // println!("msg not found");

    /* End of attack */
}

const PUZZLE_DESCRIPTION: &str = r"
Bob designed a new one time scheme, that's based on the tried and true method of encrypt + sign. He combined ElGamal encryption with BLS signatures in a clever way, such that you use pairings to verify the encrypted message was not tampered with. Alice, then, figured out a way to reveal the plaintexts...
";
