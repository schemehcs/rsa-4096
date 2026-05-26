use std::{error::Error, fmt::Display};

use crypto_bigint::{
    NonZero, Odd,
    modular::{FixedMontyForm, MontyParams},
};

pub use crypto_bigint::U4096;

use crypto_primes::{Flavor, random_prime};

pub struct PubKey {
    n: U4096,
    e: U4096,
}

pub struct PrivKey {
    n: U4096,
    d: U4096,
}

#[derive(Debug)]
pub struct CryptErr;

impl Display for CryptErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "crypt error")
    }
}

impl Error for CryptErr {}

pub fn encrypt_slice(be_slice: &[u8], pub_key: &PubKey) -> Result<Vec<u8>, CryptErr> {
    if be_slice.len() != 512 {
        return Err(CryptErr);
    }
    let x = U4096::from_be_slice(be_slice);
    if x >= pub_key.n {
        return Err(CryptErr);
    }
    Ok(encrypt_u4096(x, pub_key).to_be_bytes().to_vec())
}

pub fn encrypt_u4096(x: U4096, pub_key: &PubKey) -> U4096 {
    pow_mod(x, pub_key.e, pub_key.n)
}

pub fn decrypt_slice(be_slice: &[u8], priv_key: &PrivKey) -> Result<Vec<u8>, CryptErr> {
    if be_slice.len() != 512 {
        return Err(CryptErr);
    }
    let y = U4096::from_be_slice(be_slice);
    if y >= priv_key.n {
        return Err(CryptErr);
    }
    Ok(decrypt_u4096(y, priv_key).to_be_bytes().to_vec())
}

pub fn decrypt_u4096(y: U4096, priv_key: &PrivKey) -> U4096 {
    pow_mod(y, priv_key.d, priv_key.n)
}

pub fn rand_rsa_suite() -> (PubKey, PrivKey) {
    let mut rng = rand::rng();
    let e = U4096::from(65537u32);
    loop {
        let p: U4096 = random_prime::<U4096, _>(&mut rng, Flavor::Any, 2048);
        let q: U4096 = random_prime::<U4096, _>(&mut rng, Flavor::Any, 2048);
        let n: U4096 = p.saturating_mul(&q);
        let phi = (p - U4096::ONE).saturating_mul(&(q - U4096::ONE));
        if is_phi_valid(phi, e) {
            let opt_d = e.invert_mod(&NonZero::new(phi).unwrap());
            if opt_d.is_some().to_bool() {
                let pub_key = PubKey { n, e };
                let priv_key = PrivKey {
                    n,
                    d: opt_d.unwrap(),
                };
                return (pub_key, priv_key);
            }
        }
    }
}

fn pow_mod(base: U4096, exp: U4096, modulus: U4096) -> U4096 {
    let odd_mod = Odd::new(modulus).unwrap();
    let params = MontyParams::new(odd_mod);
    let base_mont = FixedMontyForm::new(&base, &params);
    let result_mont = base_mont.pow(&exp);
    result_mont.retrieve()
}

fn is_phi_valid(phi: U4096, e: U4096) -> bool {
    let (q, r) = phi.div_rem_vartime(&NonZero::new(e).unwrap());
    q >= U4096::ONE && !r.is_zero_vartime()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let (pub_key, priv_key) = rand_rsa_suite();

        for i in 100..105_u32 {
            let mut input = [0u8; 512];
            input[..4].copy_from_slice(&i.to_be_bytes());
            let encrypted = encrypt_slice(&input, &pub_key).unwrap();
            let decrypted = decrypt_slice(&encrypted, &priv_key).unwrap();
            assert_eq!(&input[..], &decrypted,);
        }
    }
}
