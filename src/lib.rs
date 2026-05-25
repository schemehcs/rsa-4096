use crypto_bigint::{
    NonZero, Odd, U4096,
    modular::{FixedMontyForm, MontyParams},
};
use crypto_primes::{Flavor, random_prime};

pub struct PubKey {
    n: U4096,
    e: U4096,
}

pub struct PrivKey {
    n: U4096,
    d: U4096,
}

pub fn encrypt(x: U4096, pub_key: &PubKey) -> U4096 {
    pow_mod(x, pub_key.e, pub_key.n)
}

pub fn decrypt(y: U4096, priv_key: &PrivKey) -> U4096 {
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
            let message = U4096::from(i);
            let encrypted = encrypt(message, &pub_key);
            let decrypted = decrypt(encrypted, &priv_key);
            assert_eq!(
                message, decrypted,
                "comparing message:{} vs decrypted:{}",
                message, decrypted
            );
        }
    }
}
