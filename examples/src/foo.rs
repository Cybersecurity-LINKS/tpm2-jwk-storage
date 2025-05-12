use tpm2_jwk_storage::{types::tpm_key_type::{EcCurve, TpmKeyType}, vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig}};
use std::{str::FromStr, time::Instant};

fn main(){
    let vault = TpmVault::new(TpmVaultConfig::from_str("device:/dev/tpmrm0").unwrap());
    // Benchmark execution
    for _ in 0..100{
        let random = vault.random(32).unwrap();
        let start = Instant::now();
        // code to measure
        let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), &random.try_into().unwrap()).unwrap();

        let elapsed = start.elapsed();
        println!("Time taken: {:?}", elapsed);
    }
}