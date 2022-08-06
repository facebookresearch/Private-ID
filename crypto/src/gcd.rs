//  Copyright (c) Facebook, Inc. and its affiliates.
//  SPDX-License-Identifier: Apache-2.0

use std::cmp;

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::ToBigInt;
use num_integer::Integer;
use num_traits::identities::Zero;
use num_traits::One;
use num_traits::Signed;

fn extended_binary_gcd(m: &BigUint, n: &BigUint) -> (BigInt, BigInt, BigUint) {
    #[inline]
    fn count_twos_multiple(x: &BigUint) -> u64 {
        x.trailing_zeros().unwrap_or(0)
    }

    // Assume non zero
    assert!(!m.is_zero());
    assert!(!n.is_zero());

    let mut x_ebgcd = m.clone();
    let mut y_ebgcd = n.clone();
    let mut g_ebgcd = BigUint::one();

    // find common factors of 2
    let shift = cmp::min(count_twos_multiple(&x_ebgcd), count_twos_multiple(&y_ebgcd));

    x_ebgcd >>= shift;
    y_ebgcd >>= shift;
    g_ebgcd <<= shift;

    let mut u_ebgcd = x_ebgcd.clone();
    let mut v_ebgcd = y_ebgcd.clone();

    let mut a_ebgcd = BigInt::one();
    let mut b_ebgcd = BigInt::zero();
    let mut c_ebgcd = BigInt::zero();
    let mut d_ebgcd = BigInt::one();

    loop {
        while u_ebgcd.is_even() {
            u_ebgcd >>= 1;

            if a_ebgcd.is_even() && b_ebgcd.is_even() {
                a_ebgcd >>= 1;
                b_ebgcd >>= 1;
            } else {
                a_ebgcd = (a_ebgcd + y_ebgcd.to_bigint().unwrap()) >> 1;
                b_ebgcd = (b_ebgcd - x_ebgcd.to_bigint().unwrap()) >> 1;
            }
        }

        while v_ebgcd.is_even() {
            v_ebgcd >>= 1;

            if c_ebgcd.is_even() && d_ebgcd.is_even() {
                c_ebgcd >>= 1;
                d_ebgcd >>= 1;
            } else {
                c_ebgcd = (c_ebgcd + y_ebgcd.to_bigint().unwrap()) >> 1;
                d_ebgcd = (d_ebgcd - x_ebgcd.to_bigint().unwrap()) >> 1;
            }
        }

        if u_ebgcd >= v_ebgcd {
            u_ebgcd -= &v_ebgcd;
            a_ebgcd -= &c_ebgcd;
            b_ebgcd -= &d_ebgcd;
        } else {
            v_ebgcd -= &u_ebgcd;
            c_ebgcd -= &a_ebgcd;
            d_ebgcd -= &b_ebgcd;
        }

        if u_ebgcd.is_zero() {
            return (c_ebgcd.clone(), d_ebgcd.clone(), v_ebgcd << shift);
        }
    }
}

pub fn mod_inverse(m: &BigUint, n: &BigUint) -> Option<BigInt> {
    let (mut a, _, g) = extended_binary_gcd(m, n);

    if !g.is_one() {
        return None;
    }

    let to_add = n.to_bigint().unwrap();
    if a.is_negative() {
        while a.is_negative() {
            a += &to_add;
        }
        assert!(a.is_positive());
        assert!(a < to_add);
        Some(a)
    } else {
        Some(a % to_add)
    }
}

#[cfg(test)]
mod tests {
    use std::mem;

    use num_bigint::RandBigInt;
    use num_bigint::ToBigInt;
    use num_bigint::ToBigUint;
    use num_integer::Integer;
    use num_traits::One;

    use crate::gcd::extended_binary_gcd;
    use crate::gcd::mod_inverse;

    #[test]
    fn check_mod_inv() {
        // These numbers are prime
        let x = 7919_i32.to_biguint().unwrap();
        let y = 1741_i32.to_biguint().unwrap();

        let t = mod_inverse(&x, &y);

        if t.is_some() {
            let v = (x.to_bigint().unwrap() * t.unwrap()) % y.to_bigint().unwrap();
            assert_eq!(v.is_one(), true);
        }
    }

    #[test]
    fn check_extended_gcd() {
        let x = 1021917427_i32.to_biguint().unwrap();
        let y = 48283400_i32.to_biguint().unwrap();

        let (a, b, g) = extended_binary_gcd(&x, &y);

        assert_eq!(g, x.gcd(&y));
        assert_eq!(
            a * x.to_bigint().unwrap() + b * y.to_bigint().unwrap(),
            g.to_bigint().unwrap()
        );
    }

    #[test]
    fn check_many_mod_inv_extended_gcd() {
        let mut rng = rand::thread_rng();

        for _ in 0..1000 {
            let mut x = rng.gen_biguint(2048);
            let mut y = rng.gen_biguint(2048);

            if y > x {
                mem::swap(&mut x, &mut y);
            }

            let (a, b, g) = extended_binary_gcd(&x, &y);
            assert_eq!(g, x.gcd(&y));
            assert_eq!(
                a * x.to_bigint().unwrap() + b * y.to_bigint().unwrap(),
                g.to_bigint().unwrap()
            );

            let t = mod_inverse(&x, &y);

            if t.is_some() {
                let v = (x.to_bigint().unwrap() * t.clone().unwrap()) % y.to_bigint().unwrap();
                assert_eq!(v.is_one(), true);
            }
        }
    }
}
