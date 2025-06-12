use base64::{engine::general_purpose, Engine as _};
use external_signature_program::utils::signatures::{AuthType, ClientDataJsonReconstructionParams};
use serde_cbor::Value as CborValue;
use serde_json::Value as JsonValue;

#[derive(Debug)]
pub struct WebAuthnData {
    pub signature: Vec<u8>,
    pub public_key: Option<Vec<u8>>,
    pub auth_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub client_data_json_reconstruction_params: ClientDataJsonReconstructionParams,
}

pub fn parse_webauthn_fixture(json_data: &str) -> Result<WebAuthnData, Box<dyn std::error::Error>> {
    // Parse the JSON data
    let data: JsonValue = serde_json::from_str(json_data)?;

    // Extract and decode the attestationObject
    let signature = match data["response"]["attestationObject"].as_str() {
        Some(attestation_object) => parse_signature_from_attestation_object(attestation_object)?,
        None => {
            let signature = data["response"]["signature"]
                .as_str()
                .ok_or("Missing signature")?;
            general_purpose::URL_SAFE_NO_PAD.decode(signature)?
        }
    };
    // Extract the public key
    let compressed_public_key = match data["response"]["publicKey"].as_str() {
        Some(public_key) => {
            let (x, y) = decode_ec_public_key(&public_key)?;
            // Calculate Y parity from the complete Y value
            // The parity is determined by whether Y is even or odd
            let y_parity = y[y.len() - 1] & 1; // Get the least significant bit of Y

            // Create compressed key: prefix byte (0x02 for even Y, 0x03 for odd Y) followed by X
            let mut compressed_key = vec![0x02 + y_parity]; // 0x02 for even, 0x03 for odd
            compressed_key.extend_from_slice(&x);
            Some(compressed_key)
        }
        None => None,
    };

    // Extract the message components
    let auth_data = data["response"]["authenticatorData"]
        .as_str()
        .ok_or("Missing authenticatorData")?;
    let auth_data_decoded = general_purpose::URL_SAFE_NO_PAD.decode(auth_data)?;

    let client_data_json = data["response"]["clientDataJSON"]
        .as_str()
        .ok_or("Missing clientDataJSON")?;
    let client_data_json_decoded = general_purpose::URL_SAFE_NO_PAD.decode(client_data_json)?;

    // Turn the decoded client data into json
    let client_data_json_decoded_json: JsonValue =
        serde_json::from_slice(&client_data_json_decoded)?;
    let auth_type = match client_data_json_decoded_json["type"].as_str() {
        Some("webauthn.create") => AuthType::Create,
        Some("webauthn.get") => AuthType::Get,
        _ => return Err("Invalid auth type".into()),
    };
    let cross_origin = client_data_json_decoded_json["crossOrigin"]
        .as_bool()
        .unwrap_or(false);
    let is_http = client_data_json_decoded_json["origin"]
        .as_str()
        .unwrap()
        .starts_with("http://");
    let has_google_extra =
        match client_data_json_decoded_json["other_keys_can_be_added_here"].as_str() {
            Some(_) => true,
            None => false,
        };

    // Extract port from origin URL if present (e.g. http://localhost:3000 or http://somewebsite.com)
    let port: Option<u16> = client_data_json_decoded_json["origin"]
        .as_str()
        .and_then(|s| {
            s.split("://")
                .nth(1)
                .and_then(|host| host.split(":").nth(1))
                .and_then(|port_str| port_str.parse::<u16>().ok())
        });

    let client_data_reconstruction_params = ClientDataJsonReconstructionParams::new(
        auth_type,
        cross_origin,
        is_http,
        has_google_extra,
        port,
    );
    // Return the extracted data
    Ok(WebAuthnData {
        signature,
        public_key: compressed_public_key,
        auth_data: auth_data_decoded,
        client_data_json: client_data_json_decoded,
        client_data_json_reconstruction_params: client_data_reconstruction_params,
    })
}

pub fn parse_signature_from_attestation_object(
    attestation_object: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // Decode the attestationObject from base64
    let attestation_bytes = general_purpose::URL_SAFE_NO_PAD.decode(attestation_object)?;

    // Decode the CBOR data
    let value: CborValue = serde_cbor::from_slice(&attestation_bytes)?;

    // Extract the signature from the CBOR data
    if let CborValue::Map(map) = value {
        for (key, val) in map {
            if let CborValue::Text(key_str) = key {
                if key_str == "attStmt" {
                    if let CborValue::Map(att_stmt) = val {
                        for (stmt_key, stmt_val) in att_stmt {
                            if let CborValue::Text(stmt_key_str) = stmt_key {
                                if stmt_key_str == "sig" {
                                    if let CborValue::Bytes(sig_bytes) = stmt_val {
                                        return Ok(sig_bytes);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Err("Signature not found in attestationObject".into())
}

fn decode_ec_public_key(
    public_key: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    // Base64 decode the public key
    let key_bytes = general_purpose::URL_SAFE_NO_PAD.decode(public_key)?;

    // Find the uncompressed point format marker (0x04)
    // followed by 64 bytes (32 for X, 32 for Y in P-256)
    for i in 0..key_bytes.len() - 64 {
        if key_bytes[i] == 0x04 {
            // Extract the coordinates
            let x = key_bytes[i + 1..i + 33].to_vec();
            let y = key_bytes[i + 33..i + 65].to_vec();
            return Ok((x, y));
        }
    }

    Err("Could not find EC coordinates in public key".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_webauthn_fixture() {
        // Load the fixture data
        let fixture_path = "tests/p256/fixtures/yubikey/creation.json";
        let json_data = fs::read_to_string(fixture_path).expect("Unable to read fixture file");

        // Parse the fixture
        let result = parse_webauthn_fixture(&json_data);

        // Assert the result is Ok
        assert!(result.is_ok(), "Failed to parse WebAuthn fixture");

        // Extract the parsed data
        let webauthn_data = result.unwrap();

        // Assert the extracted fields
        assert!(
            !webauthn_data.signature.is_empty(),
            "Signature should not be empty"
        );
        assert!(
            !webauthn_data.public_key.is_none(),
            "Public key should not be empty"
        );
        assert!(
            !webauthn_data.auth_data.is_empty(),
            "Auth data should not be empty"
        );
        assert!(
            !webauthn_data.client_data_json.is_empty(),
            "Client data JSON should not be empty"
        );
    }
}
