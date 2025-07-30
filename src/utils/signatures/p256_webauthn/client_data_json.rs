use base64::{engine::general_purpose, Engine as _};
use borsh::{BorshDeserialize, BorshSerialize};

/// Minimal representation for reconstructing clientDataJson
#[derive(Clone, Copy, Debug, BorshDeserialize, BorshSerialize)]
#[repr(C)]
pub struct ClientDataJsonReconstructionParams {
    /// Type and flags packed into a single byte
    pub type_and_flags: u8,
    pub port: Option<u16>,
}

/// Implementation for reconstructing clientDataJson
impl ClientDataJsonReconstructionParams {
    // Constants for type (high 4 bits)
    const TYPE_CREATE: u8 = 0x00;
    const TYPE_GET: u8 = 0x10;

    // Constants for flags (low 4 bits)
    const FLAG_CROSS_ORIGIN: u8 = 0x01;
    const FLAG_HTTP_ORIGIN: u8 = 0x02; // If not set, assume https://
    const FLAG_GOOGLE_EXTRA: u8 = 0x04; // Extra field that chrome uses to make sure the clientDataJson is not compared to a template

    /// Used to create the params (mostly for client side)
    pub fn new(
        auth_type: AuthType,
        cross_origin: bool,
        is_http: bool,
        has_google_extra: bool,
        port: Option<u16>,
    ) -> Self {
        let mut value = match auth_type {
            AuthType::Create => Self::TYPE_CREATE,
            AuthType::Get => Self::TYPE_GET,
        };

        if cross_origin {
            value |= Self::FLAG_CROSS_ORIGIN;
        }
        if is_http {
            value |= Self::FLAG_HTTP_ORIGIN;
        }
        if has_google_extra {
            value |= Self::FLAG_GOOGLE_EXTRA;
        }

        Self {
            type_and_flags: value,
            port,
        }
    }

    /// Gets the auth type from the params
    pub fn auth_type(&self) -> AuthType {
        if (self.type_and_flags & 0xF0) == Self::TYPE_GET {
            AuthType::Get
        } else {
            AuthType::Create
        }
    }

    /// Checks if the origin is cross origin
    pub fn is_cross_origin(&self) -> bool {
        self.type_and_flags & Self::FLAG_CROSS_ORIGIN != 0
    }

    /// Checks if the origin is http
    pub fn is_http(&self) -> bool {
        self.type_and_flags & Self::FLAG_HTTP_ORIGIN != 0
    }

    /// Checks if the google extra field is set
    pub fn has_google_extra(&self) -> bool {
        self.type_and_flags & Self::FLAG_GOOGLE_EXTRA != 0
    }
}

/// Enum for the auth type
#[derive(Clone, Copy, Debug)]
pub enum AuthType {
    Create,
    Get,
}

/// Reconstructs the clientDataJson from the params, rp_id and challenge.
///
/// Using the raw clientDataJson would be the ideal solution, but it takes up
/// too much space within the transaction.
///
/// Note: Due to the nature of the potential of added fields by the client, this
/// method is brittle.
pub fn reconstruct_client_data_json(
    params: &ClientDataJsonReconstructionParams,
    rp_id: &[u8],
    challenge: &[u8],
) -> Vec<u8> {
    // Encode the challenge
    let challenge_b64url = general_purpose::URL_SAFE_NO_PAD.encode(challenge);

    // Get the type string
    let type_str = match params.auth_type() {
        AuthType::Create => "webauthn.create",
        AuthType::Get => "webauthn.get",
    };

    // Get origin prefixes and port if present
    let prefix = if params.is_http() {
        "http://"
    } else {
        "https://"
    };
    // Create the origin based on the rp_id
    let origin = if let Some(port) = params.port {
        format!("{}{}:{}", prefix, std::str::from_utf8(rp_id).unwrap(), port)
    } else {
        format!("{}{}", prefix, std::str::from_utf8(rp_id).unwrap())
    };
    // Create the cross origin string
    let cross_origin = if params.is_cross_origin() {
        "true"
    } else {
        "false"
    };

    let mut json_bytes: Vec<u8> = Vec::with_capacity(256);
    json_bytes.extend_from_slice(b"{\"type\":\"");
    json_bytes.extend_from_slice(type_str.as_bytes());
    json_bytes.extend_from_slice(b"\",\"challenge\":\"");
    json_bytes.extend_from_slice(challenge_b64url.as_bytes());
    json_bytes.extend_from_slice(b"\",\"origin\":\"");
    json_bytes.extend_from_slice(origin.as_bytes());
    json_bytes.extend_from_slice(b"\",\"crossOrigin\":");
    json_bytes.extend_from_slice(cross_origin.as_bytes());

    // Add Google's extra field if needed
    // Google note: One should not compare an unparsed clientDataJSON against a
    // template. We fully reconstruct the clientDataJSON, and don't compare to a
    // template, so we arent subject to this notice. However due to the potential
    // of added fields by the client, this method could be brittle in the future.
    if params.has_google_extra() {
        json_bytes.extend_from_slice(b",\"other_keys_can_be_added_here\":\"do not compare clientDataJSON against a template. See https://goo.gl/yabPex\"");
    }

    json_bytes.extend_from_slice(b"}");

    // Note on JSON formatting: Since we never actually parse the JSON, theres
    // no attack vector on making trying to break it via escape chars etc. The raw bytes
    // are later simply hashed to get the resulting client data hash.
    json_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose;

    #[test]
    fn test_reconstruct_client_data_json() {
        // Set up the parameters
        let params = ClientDataJsonReconstructionParams::new(
            AuthType::Get, // Based on the provided type in the base64 string
            false,         // cross_origin
            false,         // is_http
            false,         // has_google_extra
            None,          // port
        );
        let rp_id = "www.passkeys-debugger.io";
        let challenge = b"hello_world";

        // Call the function
        let result = reconstruct_client_data_json(&params, rp_id.as_bytes(), challenge);

        // Base64-encoded expected JSON
        let expected_base64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYUdWc2JHOWZkMjl5YkdRIiwib3JpZ2luIjoiaHR0cHM6Ly93d3cucGFzc2tleXMtZGVidWdnZXIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9";

        // Decode the base64 string to get the expected JSON bytes
        let expected_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(expected_base64)
            .unwrap();

        // Assert that the result matches the expected bytes
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_reconstruct_client_data_json_with_extra_field() {
        // Set up the parameters with the extra field
        let params = ClientDataJsonReconstructionParams::new(
            AuthType::Get, // Based on the provided type in the base64 string
            false,         // cross_origin
            false,         // is_http
            true,          // has_google_extra
            None,          // port
        );
        let rp_id = "www.passkeys-debugger.io";
        let challenge = b"hello_world";

        // Call the function
        let result = reconstruct_client_data_json(&params, rp_id.as_bytes(), challenge);

        // Base64-encoded expected JSON with the extra field
        let expected_base64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYUdWc2JHOWZkMjl5YkdRIiwib3JpZ2luIjoiaHR0cHM6Ly93d3cucGFzc2tleXMtZGVidWdnZXIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ";

        // Decode the base64 string to get the expected JSON bytes
        let expected_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(expected_base64)
            .unwrap();

        // Assert that the result matches the expected bytes
        assert_eq!(result, expected_bytes);
    }

    #[test]
    fn test_reconstruct_client_data_json_with_port() {
        let params = ClientDataJsonReconstructionParams::new(
            AuthType::Get, // Based on the provided type in the base64 string
            false,         // cross_origin
            true,          // is_http
            false,         // has_google_extra
            Some(3000),    // port
        );
        let rp_id = "localhost";
        let challenge = b"hello_world";

        // Call the function
        let result = reconstruct_client_data_json(&params, rp_id.as_bytes(), challenge);

        // Base64-encoded expected JSON with the port
        let expected_base64 = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiYUdWc2JHOWZkMjl5YkdRIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDozMDAwIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ";

        // Decode the base64 string to get the expected JSON bytes
        let expected_bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(expected_base64)
            .unwrap();

        // Assert that the result matches the expected bytes
        assert_eq!(result, expected_bytes);
    }
}
