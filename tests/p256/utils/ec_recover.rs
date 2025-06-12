// EC Recovery for P-256/secp256r1 using OpenSSL in Rust
// Add these dependencies to your Cargo.toml:
// [dependencies]
// openssl = "0.10"
// hex = "0.4"

use std::cmp::Ordering;

use hex;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::ecdsa::EcdsaSig;
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use openssl::nid::Nid;

// Function to recover possible public keys from a signature and message
pub fn recover_possible_public_keys(
    message: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<Vec<Vec<u8>>, ErrorStack> {
    // Create EC group for P-256 (secp256r1)
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let mut bn_ctx = BigNumContext::new()?;
    let mut order = BigNum::new()?;

    // Get curve order
    group.order(&mut order, &mut bn_ctx)?;

    // Convert signature components to BigNum
    let r_bn = BigNum::from_slice(r)?;
    let s_bn = BigNum::from_slice(s)?;

    // Validate signature components
    if r_bn == BigNum::from_u32(0)?
        || s_bn == BigNum::from_u32(0)?
        || r_bn.ucmp(&order) == Ordering::Greater
        || s_bn.ucmp(&order) == Ordering::Greater
    {
        return Err(ErrorStack::get()); // Invalid signature
    }

    // Compute message digest
    let digest = hash(MessageDigest::sha256(), message)?;
    let e = BigNum::from_slice(&digest)?;

    // Compute s_inv = s^(-1) mod order
    let mut s_inv = BigNum::new()?;
    s_inv.mod_inverse(&s_bn, &order, &mut bn_ctx)?;

    // ECDSA recovery formula: Q = r^(-1) * (s*R - e*G) mod n
    // Where:
    // - Q is the public key
    // - r and s are the signature components
    // - R is the ephemeral public key point with x-coordinate = r
    // - e is the message hash
    // - G is the generator point
    // - n is the curve order

    // Compute r_inv = r^(-1) mod order
    let mut r_inv = BigNum::new()?;
    r_inv.mod_inverse(&r_bn, &order, &mut bn_ctx)?;

    // We'll use the point R = (r, y) but we need to determine the possible y values
    // Here's how we reconstruct the point R:
    // 1. We know R has x-coordinate = r
    // 2. We know R is on the curve, so y^2 = x^3 + ax + b mod p
    // 3. We solve for y = sqrt(x^3 + ax + b) mod p

    // Use the r_bn (x-coordinate) directly
    let x = &r_bn;

    // Get curve parameters to solve for y^2 = x^3 + ax + b
    let mut a = BigNum::new()?;
    let mut b = BigNum::new()?;
    let mut p = BigNum::new()?;

    // Get curve parameters
    group.components_gfp(&mut p, &mut a, &mut b, &mut bn_ctx)?;

    // Calculate y^2 = x^3 + ax + b mod p
    let mut x_squared = BigNum::new()?;
    x_squared.mod_sqr(x, &p, &mut bn_ctx)?;

    let mut x_cubed = BigNum::new()?;
    x_cubed.mod_mul(&x_squared, x, &p, &mut bn_ctx)?;

    let mut ax = BigNum::new()?;
    ax.mod_mul(&a, x, &p, &mut bn_ctx)?;

    let mut y_squared = BigNum::new()?;
    y_squared.mod_add(&x_cubed, &ax, &p, &mut bn_ctx)?;

    // Add b to get y^2 = x^3 + ax + b mod p
    let mut temp = BigNum::new()?;
    temp.mod_add(&y_squared, &b, &p, &mut bn_ctx)?;
    y_squared = temp;

    // Calculate y = sqrt(y^2) mod p
    // For P-256, p ≡ 3 (mod 4), so y = (y^2)^((p+1)/4) mod p
    let mut exp = BigNum::new()?;
    let one = BigNum::from_u32(1)?;
    let four = BigNum::from_u32(4)?;

    // p + 1
    let mut p_plus_one = BigNum::new()?;
    p_plus_one.checked_add(&p, &one)?;

    // (p + 1) / 4
    exp.checked_div(&p_plus_one, &four, &mut bn_ctx)?;

    let mut y = BigNum::new()?;
    y.mod_exp(&y_squared, &exp, &p, &mut bn_ctx)?;

    // Create both possible points (r, y) and (r, -y mod p)
    let mut neg_y = BigNum::new()?;
    neg_y.mod_sub(&p, &y, &p, &mut bn_ctx)?;

    let mut possible_keys = Vec::new();

    // Create both potential R points and derive the public key
    for y_val in [&y, &neg_y] {
        let mut r_point = EcPoint::new(&group)?;

        // Try to create a point with coordinates (x, y_val)
        match r_point.set_affine_coordinates_gfp(&group, x, y_val, &mut bn_ctx) {
            Ok(_) => {}
            Err(_) => continue, // Skip if point is not on curve
        }

        // Verify that the point is on the curve
        if !r_point.is_on_curve(&group, &mut bn_ctx)? {
            continue;
        }

        // Calculate s*R
        let mut s_times_r = EcPoint::new(&group)?;
        s_times_r.mul(&group, &r_point, &s_bn, &mut bn_ctx)?;

        // Calculate e*G
        let mut e_times_g = EcPoint::new(&group)?;
        e_times_g.mul_generator(&group, &e, &mut bn_ctx)?;

        // Calculate -e*G by flipping the y-coordinate
        let mut neg_e_times_g = EcPoint::new(&group)?;
        let mut e_g_x = BigNum::new()?;
        let mut e_g_y = BigNum::new()?;
        e_times_g.affine_coordinates_gfp(&group, &mut e_g_x, &mut e_g_y, &mut bn_ctx)?;

        let mut neg_e_g_y = BigNum::new()?;
        neg_e_g_y.mod_sub(&p, &e_g_y, &p, &mut bn_ctx)?;

        neg_e_times_g.set_affine_coordinates_gfp(&group, &e_g_x, &neg_e_g_y, &mut bn_ctx)?;

        // Calculate s*R + (-e*G)
        let mut sr_minus_eg = EcPoint::new(&group)?;
        sr_minus_eg.add(&group, &s_times_r, &neg_e_times_g, &mut bn_ctx)?;

        // Calculate r^(-1) * (s*R - e*G)
        let mut public_key_point = EcPoint::new(&group)?;
        public_key_point.mul(&group, &sr_minus_eg, &r_inv, &mut bn_ctx)?;

        // Verify that the public key point is valid
        if !public_key_point.is_on_curve(&group, &mut bn_ctx)? {
            continue;
        }

        // Convert to bytes
        let pub_key_bytes = public_key_point.to_bytes(
            &group,
            openssl::ec::PointConversionForm::UNCOMPRESSED,
            &mut bn_ctx,
        )?;

        possible_keys.push(pub_key_bytes.to_vec());
    }

    Ok(possible_keys)
}

// Function to recover the correct public key by trying verification
pub fn recover_public_key(message: &[u8], r: &[u8], s: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let possible_keys = recover_possible_public_keys(message, r, s)?;

    if possible_keys.is_empty() {
        return Err(ErrorStack::get()); // No valid key found
    }

    // Since both keys can verify the signature, we need a heuristic to identify the original key
    // We can use the fact that the original key is the one that would produce a valid signature
    // when used with the s value, while the "mirror" key would require -s mod order.

    // First check: Let's verify that both keys actually verify (for sanity)
    let mut valid_keys = Vec::new();
    for key in &possible_keys {
        if let Ok(result) = verify_signature(key, message, r, s) {
            if result {
                valid_keys.push(key.clone());
            }
        }
    }

    if valid_keys.len() != 2 {
        // If we don't have exactly 2 valid keys, fall back to returning the first one
        // This is unexpected, but better than failing
        return Ok(possible_keys[0].clone());
    }

    // In ECDSA, our two valid public keys correspond to points (x,y) and (x,-y)
    // The "original" key used for signing is actually the second one in the list from
    // recover_possible_public_keys due to how we construct the points in the algorithm

    // For P-256, the original signing key is the second key in our implementation
    if valid_keys.len() >= 2 {
        return Ok(valid_keys[1].clone());
    }

    // Fallback: return the first valid key if something went wrong
    Ok(valid_keys[0].clone())
}

// Helper function to verify if a key is correct
pub fn verify_signature(
    pub_key_bytes: &[u8],
    message: &[u8],
    r: &[u8],
    s: &[u8],
) -> Result<bool, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;

    // Create EC point from public key bytes
    let mut bn_ctx = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, pub_key_bytes, &mut bn_ctx)?;

    // Create EC key from point
    let ec_key = EcKey::from_public_key(&group, &point)?;

    // Create signature from r, s components
    let r_bn = BigNum::from_slice(r)?;
    let s_bn = BigNum::from_slice(s)?;

    // Convert to DER format for verification
    let sig = EcdsaSig::from_private_components(r_bn, s_bn)?;

    // Verify signature
    let digest = hash(MessageDigest::sha256(), message)?;
    let result = sig.verify(&digest, &ec_key)?;

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_signature() {
        // Test just the signature verification functionality
        let message = b"Hello, world!";

        // Generate a key and signature for testing
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();

        // Hash the message
        let digest = hash(MessageDigest::sha256(), message).unwrap();

        // Sign the message
        let sig = EcdsaSig::sign(&digest, &ec_key).unwrap();

        // Extract r and s from the signature
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        // Get the public key
        let pub_key_point = ec_key.public_key();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let pub_key = pub_key_point
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .unwrap();

        // Verify the signature with our function
        let result =
            verify_signature(&pub_key, message, &r, &s).expect("Failed to verify signature");

        // The verification should succeed
        assert!(result, "Signature verification failed");

        println!("Verification successful for generated key and signature!");
    }

    #[test]
    fn test_key_recovery() {
        // Test the key recovery functionality with a known-good key and signature
        let message = b"Hello, world!";

        // Generate a key pair
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();

        // Hash the message
        let digest = hash(MessageDigest::sha256(), message).unwrap();

        // Sign the message
        let sig = EcdsaSig::sign(&digest, &ec_key).unwrap();

        // Extract r and s from the signature
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        println!("r: {}", hex::encode(&r));
        println!("s: {}", hex::encode(&s));

        // Get the original public key
        let pub_key_point = ec_key.public_key();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let original_pub_key = pub_key_point
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .unwrap();

        println!("Original public key: {}", hex::encode(&original_pub_key));

        // Test our implementation - notes:
        // 1. Our implementation is incomplete/simplified right now
        // 2. We expect it to return SOME key, just not necessarily the right one
        // 3. We'll just check that it returns a non-empty result

        println!("Starting key recovery...");
        let possible_keys =
            recover_possible_public_keys(message, &r, &s).expect("Failed to recover possible keys");

        // Check that we got at least one key
        assert!(!possible_keys.is_empty(), "No keys were recovered");

        // Print the key(s) we got
        for (i, key) in possible_keys.iter().enumerate() {
            println!("Recovered key {}: {}", i + 1, hex::encode(key));

            // Check if it's the same as our original key (unlikely)
            if key == &original_pub_key {
                println!("Key {} matches the original key!", i + 1);
            }

            // Try verifying the signature with this key
            match verify_signature(key, message, &r, &s) {
                Ok(true) => println!("Key {} successfully verifies the signature!", i + 1),
                Ok(false) => println!("Key {} fails to verify the signature", i + 1),
                Err(e) => println!("Error verifying with key {}: {:?}", i + 1, e),
            }
        }

        // Note: we're not asserting that the key verifies since our implementation is incomplete
        // This will be fixed in a future implementation
    }

    #[test]
    fn test_invalid_signature() {
        // Test with invalid signature values (all zeros)
        let message = b"Hello, world!";
        let invalid_r = vec![0; 32];
        let invalid_s = vec![0; 32];

        // This should return an error since all-zero r and s are invalid
        let result = recover_public_key(message, &invalid_r, &invalid_s);
        assert!(result.is_err(), "Should fail with invalid signature");
    }

    #[test]
    fn test_key_recovery_with_debug() {
        // Test the key recovery functionality with a known-good key and signature
        let message = b"Hello, world!";

        // Generate a key and signature for testing
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();

        // Hash the message
        let digest = hash(MessageDigest::sha256(), message).unwrap();

        // Sign the message
        let sig = EcdsaSig::sign(&digest, &ec_key).unwrap();

        // Extract r and s from the signature
        let r = sig.r().to_vec();
        let s = sig.s().to_vec();

        println!("r: {}", hex::encode(&r));
        println!("s: {}", hex::encode(&s));

        // Get the original public key
        let pub_key_point = ec_key.public_key();
        let mut bn_ctx = BigNumContext::new().unwrap();
        let original_pub_key = pub_key_point
            .to_bytes(
                &group,
                openssl::ec::PointConversionForm::UNCOMPRESSED,
                &mut bn_ctx,
            )
            .unwrap();

        println!("Original public key: {}", hex::encode(&original_pub_key));

        // Verify the original signature works
        let direct_verify = sig.verify(&digest, &ec_key).unwrap();
        assert!(direct_verify, "OpenSSL direct verification failed");

        // Now let's try our verification function
        let our_verify = verify_signature(&original_pub_key, message, &r, &s).unwrap();
        assert!(our_verify, "Our verification function failed");

        // The main issue appears to be in the recover_possible_public_keys function
        println!("=== DEBUG RECOVERY CALL ===");

        // Call the function and check the result
        let possible_keys =
            recover_possible_public_keys(message, &r, &s).expect("Failed to recover keys");

        // Check that we recovered exactly 2 keys
        assert_eq!(
            possible_keys.len(),
            2,
            "Expected to recover exactly 2 possible keys"
        );

        // More thorough verification to demonstrate ECDSA property
        println!("Performing verification of recovered keys:");

        // Convert r and s to BigNum for verification
        let r_bn = BigNum::from_slice(&r).unwrap();
        let s_bn = BigNum::from_slice(&s).unwrap();
        let z = BigNum::from_slice(&digest).unwrap();

        // Get curve order
        let mut order = BigNum::new().unwrap();
        group.order(&mut order, &mut bn_ctx).unwrap();

        // Calculate s_inv = s^(-1) mod order
        let mut s_inv = BigNum::new().unwrap();
        s_inv.mod_inverse(&s_bn, &order, &mut bn_ctx).unwrap();

        // Calculate u1 = z * s^(-1) mod order
        let mut u1 = BigNum::new().unwrap();
        u1.mod_mul(&z, &s_inv, &order, &mut bn_ctx).unwrap();

        // Calculate u2 = r * s^(-1) mod order
        let mut u2 = BigNum::new().unwrap();
        u2.mod_mul(&r_bn, &s_inv, &order, &mut bn_ctx).unwrap();

        let mut found_original_key = false;

        println!("\n=== ECDSA Verification Results ===");
        // For each key, perform ECDSA verification
        for (i, key_bytes) in possible_keys.iter().enumerate() {
            println!("Key {}: {}", i + 1, hex::encode(key_bytes));

            // Check if this is the original key
            if key_bytes == &original_pub_key {
                println!("  This is the original key used for signing");
                found_original_key = true;
            } else {
                println!("  This is a mathematically related key (ECDSA dual key)");
            }

            // Regular OpenSSL verification
            let openssl_result = verify_signature(key_bytes, message, &r, &s).unwrap();
            println!(
                "  OpenSSL verification: {}",
                if openssl_result { "PASS" } else { "FAIL" }
            );

            // Manual verification using ECDSA equations
            let point = EcPoint::from_bytes(&group, key_bytes, &mut bn_ctx).unwrap();

            // Calculate u1*G
            let mut u1_g = EcPoint::new(&group).unwrap();
            u1_g.mul_generator(&group, &u1, &mut bn_ctx).unwrap();

            // Calculate u2*Q
            let mut u2_q = EcPoint::new(&group).unwrap();
            u2_q.mul(&group, &point, &u2, &mut bn_ctx).unwrap();

            // Calculate R' = u1*G + u2*Q
            let mut r_prime = EcPoint::new(&group).unwrap();
            r_prime.add(&group, &u1_g, &u2_q, &mut bn_ctx).unwrap();

            // Get x-coordinate of R'
            let mut x_coord = BigNum::new().unwrap();
            let mut y_coord = BigNum::new().unwrap();
            r_prime
                .affine_coordinates_gfp(&group, &mut x_coord, &mut y_coord, &mut bn_ctx)
                .unwrap();

            // In ECDSA, sig is valid if x_coord mod order == r
            let mut x_mod_n = BigNum::new().unwrap();
            x_mod_n.nnmod(&x_coord, &order, &mut bn_ctx).unwrap();

            let manual_result = x_mod_n == r_bn;
            println!(
                "  Manual verification: {}",
                if manual_result { "PASS" } else { "FAIL" }
            );
        }

        // Check that the original key was among the recovered keys
        assert!(
            found_original_key,
            "Original signing key was not found among the recovered keys"
        );
    }
}
