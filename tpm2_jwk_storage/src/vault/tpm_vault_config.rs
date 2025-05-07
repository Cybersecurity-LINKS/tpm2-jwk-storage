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

use tss_esapi::Tcti;

/// Configuration Wrapper for the `TpmVault`
pub type TpmVaultConfig = Tcti;

#[cfg(test)]
mod tests {

    use super::TpmVaultConfig;
    use std::str::FromStr;

    #[test]
    fn device_config(){
        let config = TpmVaultConfig::from_str("device:/dev/tpm0");
        assert!(config.is_ok())
    }

    #[test]
    fn sim_config(){
        let config = TpmVaultConfig::from_str("swtpm:host=127.0.0.1,port=2321");
        assert!(config.is_ok());
        let config = TpmVaultConfig::from_str("mssim:host=127.0.0.1,port=2321");
        assert!(config.is_ok());
    }

    #[test]
    fn tabrmd_config(){
        let config = TpmVaultConfig::from_str("tabrmd");
        assert!(config.is_ok());
    }
}