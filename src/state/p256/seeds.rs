pub struct AccountSeeds {
    pub key: Pubkey,
    pub bump: u8,
    seed_passkey: &'static [u8],
    seed_public_key_hash: [u8; 32],
}

impl AccountSeedsTrait for AccountSeeds {
    fn key(&self) -> &Pubkey {
        &self.key
    }
    fn bump(&self) -> u8 {
        self.bump
    }
    fn seeds(&self) -> Vec<&[u8]> {
        vec![
            self.seed_passkey,
            &self.seed_public_key_hash,
            core::slice::from_ref(&self.bump),
        ]
    }
}