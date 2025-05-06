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

use super::{error::TpmVaultError, tpm_vault_config::TPMConfig};
/// Performs key management operation using TSS 2.0 ESAPI wrapper.
/// 
/// It tries to connect to the TPM 2.0 pointed by the provided configuration
pub struct TpmVault{
    //ctx: Mutex<Context>,
    //session: Arc<Option<AuthSession>>,
    //cache: RwLock<TpmObjectCache>  
}

impl TpmVault{
    /// Create a new instance with a given configuration
    pub fn new(config: TPMConfig) -> Result<Self, TpmVaultError>{
        Err(TpmVaultError::TpmConfigError(String::from("")))
    }
}