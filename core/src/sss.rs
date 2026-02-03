//! Shamir's Secret Sharing (SSS) implementation.
//!
//! This module implements Shamir's Secret Sharing over a finite field defined by a prime `p`.
//! It is used by the Clevis pin to split a secret into multiple shares and recover it.

use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, Zero, FromPrimitive};
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// SSS configuration containing the prime and coefficients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SssConfig {
    /// Prime modulus defining the finite field.
    pub p: BigUint,
    /// Coefficients of the polynomial (e[0] is the secret, e[1..] are random).
    /// The polynomial is of degree `threshold-1`.
    pub e: Vec<BigUint>,
    /// Threshold (minimum number of shares needed for recovery).
    pub t: usize,
}

impl SssConfig {
    /// Creates a new SSS configuration for a given key size and threshold.
    ///
    /// # Arguments
    ///
    /// * `key_bytes` - Size of the secret in bytes.
    /// * `threshold` - Minimum number of shares required to recover the secret.
    ///
    /// # Returns
    ///
    /// A new `SssConfig` with a random prime of size `key_bytes * 8` bits and random coefficients.
    pub fn generate(key_bytes: usize, threshold: usize) -> Result<Self> {
        if key_bytes == 0 || threshold < 1 {
            return Err(Error::validation(
                "key_bytes must be positive and threshold at least 1".to_string(),
            ));
        }

        let mut rng = rand::thread_rng();

        // Generate a prime p of size key_bytes * 8 bits.
        // Note: We use a probabilistic prime generation, which is acceptable for this use case.
        let p = rng.gen_prime(key_bytes * 8);

        // Generate random coefficients e[0..threshold-1].
        // e[0] is the secret (we generate it randomly, but in practice it will be provided by the user).
        let mut e = Vec::with_capacity(threshold);
        for _ in 0..threshold {
            let coeff = rng.gen_range(BigUint::zero()..p.clone());
            e.push(coeff);
        }

        Ok(SssConfig { p, e, t: threshold })
    }

    /// Evaluates the polynomial at a random point x (mod p) and returns the point (x, y).
    ///
    /// # Returns
    ///
    /// A byte vector containing x || y, each of size key_bytes (determined by the prime size).
    pub fn point(&self) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();

        // Choose a random x in [0, p-1]
        let x = rng.gen_range(BigUint::zero()..self.p.clone());

        // Compute y = polynomial evaluated at x (mod p)
        let y = self.evaluate_polynomial(&x);

        // Convert x and y to bytes of fixed length (key_bytes)
        let key_bytes = ((self.p.bits() + 7) / 8) as usize;
        let mut result = vec![0u8; key_bytes * 2];
        let x_bytes = x.to_bytes_be();
        let y_bytes = y.to_bytes_be();

        // Copy bytes with right alignment (big-endian)
        let x_start = key_bytes - x_bytes.len();
        let y_start = 2 * key_bytes - y_bytes.len();
        result[x_start..x_start + x_bytes.len()].copy_from_slice(&x_bytes);
        result[y_start..y_start + y_bytes.len()].copy_from_slice(&y_bytes);

        Ok(result)
    }

    /// Evaluates the polynomial at a given x.
    fn evaluate_polynomial(&self, x: &BigUint) -> BigUint {
        // Use Horner's method: y = e[0] + e[1]*x + e[2]*x^2 + ... + e[t-1]*x^{t-1} (mod p)
        let mut y = BigUint::zero();
        for coeff in self.e.iter().rev() {
            y = (y * x + coeff) % &self.p;
        }
        y
    }
}

/// Recovers the secret from a set of points.
///
/// # Arguments
///
/// * `p` - The prime modulus.
/// * `points` - A slice of byte arrays, each being x || y of the same length.
///
/// # Returns
///
/// The recovered secret as a byte vector (without leading zeros).
pub fn recover(p: &BigUint, points: &[Vec<u8>]) -> Result<Vec<u8>> {
    if points.is_empty() {
        return Err(Error::validation("No points provided for recovery".to_string()));
    }

    let key_bytes = points[0].len() / 2;
    if key_bytes == 0 {
        return Err(Error::validation("Invalid point length".to_string()));
    }

    // Convert points to (x, y) BigUints
    let mut points_xy: Vec<(BigUint, BigUint)> = Vec::with_capacity(points.len());
    for point in points {
        if point.len() != 2 * key_bytes {
            return Err(Error::validation("Points have inconsistent lengths".to_string()));
        }
        let x = BigUint::from_bytes_be(&point[..key_bytes]);
        let y = BigUint::from_bytes_be(&point[key_bytes..]);
        points_xy.push((x, y));
    }

    // Use Lagrange interpolation to recover the secret (which is the polynomial evaluated at 0).
    let secret = lagrange_interpolation(0, &points_xy, p)?;

    // Return the secret as bytes (without leading zeros)
    Ok(secret.to_bytes_be())
}

/// Performs Lagrange interpolation in the finite field defined by prime p.
///
/// # Arguments
///
/// * `x` - The x-coordinate to evaluate the polynomial at (we use 0 to get the constant term).
/// * `points` - A slice of (x, y) points.
/// * `p` - The prime modulus.
///
/// # Returns
///
/// The interpolated value at x (mod p).
fn lagrange_interpolation(
    x: u32,
    points: &[(BigUint, BigUint)],
    p: &BigUint,
) -> Result<BigUint> {
    let x_big = BigUint::from_u32(x).unwrap();

    let mut result = BigUint::zero();
    for (j, (xj, yj)) in points.iter().enumerate() {
        let mut numerator = BigUint::one();
        let mut denominator = BigUint::one();

        for (m, (xm, _)) in points.iter().enumerate() {
            if m == j {
                continue;
            }

            // numerator *= (x - xm)
            let x_minus_xm = if &x_big >= xm {
                &x_big - xm
            } else {
                p - (xm - &x_big)
            };
            numerator = (numerator * x_minus_xm) % p;

            // denominator *= (xj - xm)
            let xj_minus_xm = if xj >= xm {
                xj - xm
            } else {
                p - (xm - xj)
            };
            denominator = (denominator * xj_minus_xm) % p;
        }

        // Compute term = yj * numerator * denominator^{-1} mod p
        let denom_inv = mod_inverse(&denominator, p)?;
        let term = (yj * numerator) % p;
        let term = (term * denom_inv) % p;

        result = (result + term) % p;
    }

    Ok(result)
}

/// Computes the modular inverse of a number modulo p (using Fermat's little theorem).
fn mod_inverse(a: &BigUint, p: &BigUint) -> Result<BigUint> {
    // a^{p-2} mod p
    let exponent = p - BigUint::from_u32(2).unwrap();
    let inv = a.modpow(&exponent, p);
    Ok(inv)
}

/// Generates a random prime of the specified bit length.
trait GenPrime {
    fn gen_prime(&mut self, bits: usize) -> BigUint;
}

impl<R: Rng> GenPrime for R {
    fn gen_prime(&mut self, bits: usize) -> BigUint {
        // Generate random numbers until we find a prime (probabilistic).
        // This is similar to the original C code which uses BN_generate_prime_ex.
        loop {
            // Generate a random number with exactly `bits` bits.
            // We generate a random number in the range [2^(bits-1), 2^bits - 1]
            let low = BigUint::from(1u32) << (bits - 1);
            let high = (BigUint::from(1u32) << bits) - 1u32;
            let mut candidate = self.gen_range(low..=high);
            // Ensure it's odd
            if candidate.is_even() {
                candidate += 1u32;
            }
            if is_prime(&candidate, 20) {
                return candidate;
            }
        }
    }
}

/// Miller-Rabin primality test (probabilistic).
fn is_prime(n: &BigUint, k: usize) -> bool {
    if n.is_zero() || n.is_one() {
        return false;
    }
    if n == &BigUint::from_u32(2).unwrap() || n == &BigUint::from_u32(3).unwrap() {
        return true;
    }
    if n.is_even() {
        return false;
    }

    let one = BigUint::one();
    let two = BigUint::from_u32(2).unwrap();
    let n_minus_one = n - &one;

    // Write n-1 as d * 2^s
    let mut s = 0;
    let mut d = n_minus_one.clone();
    while d.is_even() {
        d >>= 1;
        s += 1;
    }

    let mut rng = rand::thread_rng();
    for _ in 0..k {
        let a = rng.gen_range(two.clone()..n_minus_one.clone());
        let mut x = a.modpow(&d, n);

        if x == one || x == n_minus_one {
            continue;
        }

        let mut continue_loop = false;
        for _ in 0..s - 1 {
            x = x.modpow(&two, n);
            if x == n_minus_one {
                continue_loop = true;
                break;
            }
        }
        if continue_loop {
            continue;
        }

        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sss_generate() {
        let config = SssConfig::generate(32, 3).unwrap();
        assert_eq!(config.e.len(), 3);
        assert!(config.p.bits() >= 32 * 8);
    }

    #[test]
    fn test_sss_point() {
        let config = SssConfig::generate(16, 2).unwrap();
        let point = config.point().unwrap();
        // point length should be 2 * key_bytes
        let key_bytes = ((config.p.bits() + 7) / 8) as usize;
        assert_eq!(point.len(), 2 * key_bytes);
    }

    #[test]
    fn test_recover() {
        // Generate a secret and split it into 5 shares with threshold 3.
        let config = SssConfig::generate(16, 3).unwrap();
        let mut points = Vec::new();
        for _ in 0..5 {
            points.push(config.point().unwrap());
        }

        // Recover using any 3 points
        let recovered = recover(&config.p, &points[0..3]).unwrap();
        // The recovered secret should be e[0] (the constant term) as bytes.
        let secret_bytes = config.e[0].to_bytes_be();
        assert_eq!(recovered, secret_bytes);
    }
}
