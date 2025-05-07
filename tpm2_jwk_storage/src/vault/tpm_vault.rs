// Copyright 2025 Fondazione LINKS
 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
 
//     http://www.apache.org/licenses/LICENSE-2.0
 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tss_esapi::Context;

use super::{error::TpmVaultError, tpm_vault_config::TpmVaultConfig};
/// Performs key management operations using TSS 2.0 ESAPI wrapper.
/// 
/// It tries to connect to the TPM 2.0 pointed by the provided configuration
pub struct TpmVault{
    //ctx: Mutex<Context>,
    //session: Arc<Option<AuthSession>>,
    //cache: RwLock<TpmObjectCache>
    /// Tpm configuration used for connection
    config: TpmVaultConfig
}

impl TpmVault{
    /// Create a new instance with a given configuration
    /// ### Examples
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use std::str::FromStr;
    /// 
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("device:/dev/tpmrm0").unwrap();
    /// let vault = TpmVault::new(config);
    /// ```
    pub fn new(config: TpmVaultConfig) -> Self {
        TpmVault { config }
    }

    /// Retrieve random bytes from the TPM TRNG
    /// ### Input
    /// * `size` - Number of random bytes to generate
    /// 
    /// ### Output
    /// `Vec<u8>` containing random bytes
    /// 
    /// ### Examples
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use std::str::FromStr;
    /// 
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("device:/dev/tpmrm0").unwrap();
    /// let vault = TpmVault::new(config);
    /// let random = vault.random(32);
    /// ```
    pub fn random(&self, size: usize) -> Result<Vec<u8>, TpmVaultError> {
        let mut ctx = self.connect()?;
        let random = ctx.get_random(size)?;
        Ok(random.to_vec())
    } 

    fn connect(&self) -> Result<Context, TpmVaultError>{
        Context::new(self.config.clone())
            .map_err(|e| TpmVaultError::ConnectionError(e))
    }
}