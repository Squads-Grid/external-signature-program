use std::convert::TryInto;

/// Wrapper for parsing webauthn authenticator data
pub struct AuthDataParser<'a> {
    auth_data: &'a [u8],
}

impl<'a> AuthDataParser<'a> {
    /// Creates a new AuthDataParser
    pub fn new(auth_data: &'a [u8]) -> Self {
        Self { auth_data }
    }

    /// Gets the RP ID hash
    pub fn rp_id_hash(&self) -> &'a [u8] {
        &self.auth_data[0..32]
    }

    /// Checks if the user is present based on the flags
    pub fn is_user_present(&self) -> bool {
        // User presence is indicated by the first bit of the flags byte
        self.auth_data[32] & 0x01 != 0
    }

    /// Checks if the user is verified based on the flags
    pub fn is_user_verified(&self) -> bool {
        // User verification is indicated by the second bit of the flags byte
        self.auth_data[32] & 0x04 != 0
    }

    /// Gets the counter from the authenticator data
    pub fn get_counter(&self) -> u32 {
        u32::from_be_bytes(self.auth_data[33..37].try_into().unwrap())
    }

    // DEAD CODE
    // // Verifies and parses the public key from the authenticator data
    // pub fn verify_and_parse_public_key(&self) -> Result<[u8; 33], ExternalSignatureProgramError> {
    //     // Parse credential data sections
    //     let attested_cred_data_start = 37; // rpIdHash(32) + flags(1) + counter(4)
    //     let aaguid_length = 16;
    //     let cred_id_len_index = attested_cred_data_start + aaguid_length;

    //     // Get credential ID length
    //     let cred_id_length = u16::from_be_bytes(
    //         self.auth_data[cred_id_len_index..cred_id_len_index + 2]
    //             .try_into()
    //             .unwrap(),
    //     ) as usize;

    //     // Start of CBOR-encoded public key
    //     let cbor_start = cred_id_len_index + 2 + cred_id_length;

    //     // We expect CBOR to start with a map (0xa#) where # is the number of items
    //     if cbor_start >= self.auth_data.len() || (self.auth_data[cbor_start] & 0xF0) != 0xA0 {
    //         return Err(ExternalSignatureProgramError::P256InvalidPublicKeyEncoding);
    //     }

    //     // Check for algorithm (-7)
    //     // Algorithm key is 3, followed by negative integer marker for -7 (0x26)
    //     let mut alg_found = false;
    //     for i in cbor_start..self.auth_data.len() - 1 {
    //         if self.auth_data[i] == 0x03 && self.auth_data[i + 1] == 0x26 {
    //             alg_found = true;
    //             break;
    //         }
    //     }

    //     if !alg_found {
    //         return Err(ExternalSignatureProgramError::P256InvalidAlgorithm);
    //     }

    //     // Find the x-coordinate by looking for key -2 (0x21) followed by byte string marker (0x58 0x20)
    //     let mut x_start = 0;
    //     for i in cbor_start..self.auth_data.len() - 3 {
    //         if self.auth_data[i] == 0x21
    //             && self.auth_data[i + 1] == 0x58
    //             && self.auth_data[i + 2] == 0x20
    //         {
    //             x_start = i + 3;
    //             break;
    //         }
    //     }

    //     // Find the y-coordinate by looking for key -3 (0x22) followed by byte string marker (0x58 0x20)
    //     let mut y_start = 0;
    //     for i in cbor_start..self.auth_data.len() - 3 {
    //         if self.auth_data[i] == 0x22
    //             && self.auth_data[i + 1] == 0x58
    //             && self.auth_data[i + 2] == 0x20
    //         {
    //             y_start = i + 3;
    //             break;
    //         }
    //     }

    //     // Verify we found the coordinates
    //     if x_start == 0
    //         || y_start == 0
    //         || x_start + 32 > self.auth_data.len()
    //         || y_start + 32 > self.auth_data.len()
    //     {
    //         return Err(ExternalSignatureProgramError::P256InvalidPublicKeyEncoding);
    //     }

    //     // Extract x coordinate
    //     let x = &self.auth_data[x_start..x_start + 32];

    //     // Extract y coordinate and check parity for compressed format
    //     let y = &self.auth_data[y_start..y_start + 32];
    //     let y_parity = y[31] & 0x01;

    //     // Create compressed SEC1 format (33 bytes)
    //     let mut public_key = [0u8; 33];
    //     public_key[0] = 0x02 | y_parity; // 0x02 for even y, 0x03 for odd y
    //     public_key[1..33].copy_from_slice(x);

    //     Ok(public_key)
    // }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    #[test]
    fn test_auth_data_parsing_get() {
        // Base64URL-encoded authData for get
        let auth_data_b64url = "PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkMFAAAAAA";

        // Decode the Base64URL-encoded authData
        let auth_data = general_purpose::URL_SAFE_NO_PAD
            .decode(auth_data_b64url)
            .unwrap();

        // Create an AuthDataParser instance
        let parser = AuthDataParser::new(&auth_data);

        // Verify the counter is 0
        assert_eq!(parser.get_counter(), 0);

        // Compute the expected RP ID hash
        let rp_id = "www.passkeys-debugger.io";
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected_rp_id_hash = hasher.finalize();

        // Verify the RP ID hash
        assert_eq!(parser.rp_id_hash(), expected_rp_id_hash.as_slice());

        // Verify user presence and verification flags
        assert!(parser.is_user_present());
        assert!(parser.is_user_verified());
    }

    #[test]
    fn test_auth_data_parsing_get_2() {
        // Base64URL-encoded authData for get
        let auth_data_b64url = "PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkMFAAAAAA";

        // Decode the Base64URL-encoded authData
        let auth_data = general_purpose::URL_SAFE_NO_PAD
            .decode(auth_data_b64url)
            .unwrap();

        // Create an AuthDataParser instance
        let parser = AuthDataParser::new(&auth_data);

        // Verify the counter is 0
        assert_eq!(parser.get_counter(), 0);

        // Compute the expected RP ID hash
        let rp_id = "www.passkeys-debugger.io";
        let mut hasher = Sha256::new();
        hasher.update(rp_id.as_bytes());
        let expected_rp_id_hash = hasher.finalize();

        // Verify the RP ID hash
        assert_eq!(parser.rp_id_hash(), expected_rp_id_hash.as_slice());

        // Verify user presence and verification flags
        assert!(parser.is_user_present());
        assert!(parser.is_user_verified());
    }

    // #[test]
    // fn test_auth_data_parsing_create() {
    //     // Base64URL-encoded authData for create
    //     let auth_data_b64url = "PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNFAAAAALU5dmZIhaprzr_lImKkOaIAIG8A_aee8QfsX23yu3-IWgy6OXYUsXkYwhQmlMwrG644pQECAyYgASFYIGpEZR4STYZTXI45dITdL8sb9mCYLfftOowgAZ8eAbfoIlggCwFsS4V29POWSp1_sHob7zxbIRflut4ZQkcQo_-jyyE";
    //     // Decode the Base64URL-encoded authData
    //     let auth_data = general_purpose::URL_SAFE_NO_PAD
    //         .decode(auth_data_b64url)
    //         .unwrap();
    //     // Create an AuthDataParser instance
    //     let parser = AuthDataParser::new(&auth_data);

    //     // Other assertions unchanged...

    //     // Verify and parse the public key
    //     let public_key = parser
    //         .verify_and_parse_public_key()
    //         .expect("Failed to parse public key");

    //     // Expected public key in SubjectPublicKeyInfo format
    //     let expected_public_key_b64url = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEakRlHhJNhlNcjjl0hN0vyxv2YJgt9-06jCABnx4Bt-gLAWxLhXb085ZKnX-wehvvPFshF-W63hlCRxCj_6PLIQ";
    //     let spki_key = general_purpose::URL_SAFE_NO_PAD
    //         .decode(expected_public_key_b64url)
    //         .unwrap();

    //     // The raw public key starts at offset 27 in the SubjectPublicKeyInfo format
    //     // Format is 0x04 (uncompressed) followed by x and y coordinates (32 bytes each)
    //     let raw_key = &spki_key[26..];

    //     // x-coordinate is bytes 1-33 of the uncompressed key
    //     assert_eq!(&public_key[1..33], &raw_key[1..33], "X-coordinate mismatch");

    //     // y-coordinate is bytes 33-65 of the uncompressed key
    //     let y_coord = &raw_key[33..65];

    //     // For compression, we check if the last byte of y is odd or even
    //     let expected_compression_byte = if (y_coord[31] & 0x01) == 0 {
    //         0x02
    //     } else {
    //         0x03
    //     };

    //     // Check if the compression byte matches what we expect based on y's parity
    //     assert_eq!(
    //         public_key[0], expected_compression_byte,
    //         "Incorrect compression byte"
    //     );
    // }

    // #[test]
    // fn test_auth_data_parsing_create_2() {
    //     // Base64URL-encoded authData for create
    //     let auth_data_b64url = "PpZrl-Wqt-OFfBpyy2SraN1m7LT0GZORwGA7-6ujYkNdAAAAAPv8MAcVTk7MjAtuAgVX170AFL-rjKE_pO1t0a2ZsQQYLXkEpQfspQECAyYgASFYIAfULi-U2a1hNUabTLW9XiEmauvrmQ8hG7YztEyvAl5HIlgguBLfOJ2Ju0xxBdR9fiLYdutlgqIgFvmUuk-P-VlOy6k";
    //     // Decode the Base64URL-encoded authData
    //     let auth_data = general_purpose::URL_SAFE_NO_PAD
    //         .decode(auth_data_b64url)
    //         .unwrap();
    //     // Create an AuthDataParser instance
    //     let parser = AuthDataParser::new(&auth_data);

    //     // Other assertions unchanged...

    //     // Verify and parse the public key
    //     let public_key = parser
    //         .verify_and_parse_public_key()
    //         .expect("Failed to parse public key");

    //     // Expected public key in SubjectPublicKeyInfo format
    //     let expected_public_key_b64url = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEB9QuL5TZrWE1RptMtb1eISZq6-uZDyEbtjO0TK8CXke4Et84nYm7THEF1H1-Ith262WCoiAW-ZS6T4_5WU7LqQ";
    //     let spki_key = general_purpose::URL_SAFE_NO_PAD
    //         .decode(expected_public_key_b64url)
    //         .unwrap();

    //     // The raw public key starts at offset 27 in the SubjectPublicKeyInfo format
    //     // Format is 0x04 (uncompressed) followed by x and y coordinates (32 bytes each)
    //     let raw_key = &spki_key[26..];

    //     // x-coordinate is bytes 1-33 of the uncompressed key
    //     assert_eq!(&public_key[1..33], &raw_key[1..33], "X-coordinate mismatch");

    //     // y-coordinate is bytes 33-65 of the uncompressed key
    //     let y_coord = &raw_key[33..65];

    //     // For compression, we check if the last byte of y is odd or even
    //     let expected_compression_byte = if (y_coord[31] & 0x01) == 0 {
    //         0x02
    //     } else {
    //         0x03
    //     };

    //     // Check if the compression byte matches what we expect based on y's parity
    //     assert_eq!(
    //         public_key[0], expected_compression_byte,
    //         "Incorrect compression byte"
    //     );
    // }
}
