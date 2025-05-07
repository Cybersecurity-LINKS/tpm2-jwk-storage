use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
use std::str::FromStr;

fn main(){
    TpmVault::new(TpmVaultConfig::from_str("device:/dev/tpmrm0").unwrap());
}