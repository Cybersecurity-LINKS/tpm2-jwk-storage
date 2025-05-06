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

use std::{ops::Deref, str::FromStr};

use tss_esapi::Tcti;

use super::error::TpmVaultError;

/// Configuration Wrapper for the `TpmVault`
pub struct TPMConfig(String);

impl TryInto<Tcti> for TPMConfig {
    type Error = TpmVaultError;
    
    fn try_into(self) -> Result<Tcti, Self::Error> {
        Tcti::from_str(&self.0)
        .map_err(|_| TpmVaultError::TpmConfigError(self.0))
    }
}

impl Deref for TPMConfig{
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use tss_esapi::Tcti;

    use super::TPMConfig;

    #[test]
    fn device_config(){
        let config = TPMConfig("device:/dev/tpm0".to_owned());
        assert!(TryInto::<Tcti>::try_into(config).is_ok())
    }

    #[test]
    fn sim_config(){
        let config = TPMConfig("swtpm:host=127.0.0.1,port=2321".to_owned());
        assert!(TryInto::<Tcti>::try_into(config).is_ok());
        let config = TPMConfig("mssim:host=127.0.0.1,port=2321".to_owned());
        assert!(TryInto::<Tcti>::try_into(config).is_ok());
    }

    #[test]
    fn tabrmd_config(){
        let config = TPMConfig("tabrmd".to_owned());
        assert!(TryInto::<Tcti>::try_into(config).is_ok());
    }
}