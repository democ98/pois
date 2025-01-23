pub mod hash_2_prime;
pub mod multi_level_acc;

use num_bigint_dig::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use rsa::{PublicKeyParts, RsaPrivateKey};

use hash_2_prime::h_prime;

#[derive(Clone, Default, Debug)]
pub struct RsaKey {
    pub n: BigUint, //Z/nZ
    pub g: BigUint, // Generator
}

impl RsaKey {
    pub(crate) fn new(n: BigUint, g: BigUint) -> RsaKey {
        Self { n, g }
    }
}

// Generate N and G
// lamda is the bit size of N(preferably 2048 bit)
// Note that the primes factors of N are not exposed for security reason
pub fn rsa_keygen(lambda: usize) -> RsaKey {
    let mut rng = rand::thread_rng();
    let pk = RsaPrivateKey::new(&mut rng, lambda).expect("Failed to generate RSA key");

    let n = pk.n();
    let mut f: BigUint;
    loop {
        f = rng.gen_biguint(lambda);
        if f.gcd(n) == BigUint::one() {
            break;
        }
    }
    let g = f.modpow(&BigUint::from(2u32), &n.clone());

    RsaKey { n: n.clone(), g }
}

pub fn generate_acc(key: &RsaKey, acc: &[u8], elems: Vec<Vec<u8>>) -> Option<Vec<u8>> {
    if acc.is_empty() {
        return None;
    }

    let mut g = BigUint::from_bytes_be(acc);
    for elem in elems {
        let prime = h_prime(&BigUint::from_bytes_be(&elem));
        g = g.modpow(&prime, &key.n);
    }

    Some(g.to_bytes_be())
}
