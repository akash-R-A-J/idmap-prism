use anyhow::{Result, anyhow};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::Arc;
use serde::{Deserialize, Serialize};

use spl_token_2022::extension::BaseStateWithExtensions;

#[derive(Clone)]
pub struct SolanaClientWrapper {
    client: Arc<RpcClient>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ciphertext {
    pub c1: [u8; 32],
    pub c2: [u8; 32],
}

impl SolanaClientWrapper {
    pub fn new(rpc_url: &str) -> Self {
        let client = RpcClient::new(rpc_url.to_string());
        Self {
            client: Arc::new(client),
        }
    }

    /// Fetches the Token-2022 Account Data and extracts the ElGamal ciphertext
    /// for the confidential balance.
    /// 
    /// Note: Implementation for MVP assumes standard Layout.
    /// In a real prod environment we would parse the TLV data of Token-2022 extension.
    pub async fn fetch_ciphertext(&self, wallet: &str, mint: &str) -> Result<Ciphertext> {
        let wallet_pk = Pubkey::from_str(wallet)?;
        let mint_pk = Pubkey::from_str(mint)?;

        // Find the Associated Token Account (ATA)
        let ata = spl_associated_token_account::get_associated_token_address_with_program_id(
            &wallet_pk,
            &mint_pk,
            &spl_token_2022::id(),
        );

        // Fetch Account Data
        let account = self.client.get_account(&ata).await
            .map_err(|e| anyhow!("Failed to fetch account {}: {}", ata, e))?;

        // Parse Token-2022 State to find ConfidentialTransfer extension
        use spl_token_2022::extension::StateWithExtensions;
        use spl_token_2022::state::Account;

        let state = StateWithExtensions::<Account>::unpack(&account.data)
            .map_err(|e| anyhow!("Failed to unpack Token-2022 account: {}", e))?;

        let extension = state.get_extension::<spl_token_2022::extension::confidential_transfer::ConfidentialTransferAccount>()
            .map_err(|e| anyhow!("Account missing Confidential Transfer extension: {}", e))?;

        let encrypted = extension.available_balance;
        let bytes = encrypted.0; 
        let c1: [u8; 32] = bytes[0..32].try_into().unwrap();
        let c2: [u8; 32] = bytes[32..64].try_into().unwrap();

        Ok(Ciphertext { c1, c2 })
    }
}
