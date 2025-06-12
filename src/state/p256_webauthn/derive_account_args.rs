use super::{P256ParsedInitializationData, P256ParsedVerificationData};

pub struct P256DeriveAccountArgs {
    pub public_key: [u8; 33],
}

impl<'a> From<&'a P256ParsedInitializationData> for P256DeriveAccountArgs {
    fn from(data: &'a P256ParsedInitializationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}

impl<'a> From<&'a P256ParsedVerificationData> for P256DeriveAccountArgs {
    fn from(data: &'a P256ParsedVerificationData) -> Self {
        Self {
            public_key: data.public_key.to_bytes(),
        }
    }
}
