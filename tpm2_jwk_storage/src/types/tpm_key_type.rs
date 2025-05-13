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

use std::fmt::Display;

#[cfg(feature = "iota")]
use identity_iota::storage::KeyStorageResult;
#[cfg(feature = "iota")]
use identity_iota::verification::jws::JwsAlgorithm;
use tss_esapi::interface_types::{algorithm::HashingAlgorithm, ecc::EccCurve};

use crate::vault::error::TpmVaultError;

/// Supported key types for creation of TPM key objects
#[derive(Debug)]
pub enum TpmKeyType{
    EC(EcCurve)
}

#[cfg(feature = "iota")]
impl TpmKeyType{
    pub (crate) fn check_key_alg_compatibility(&self, alg: &JwsAlgorithm) -> KeyStorageResult<()>{
        use identity_iota::storage::{KeyStorageError, KeyStorageErrorKind};
        match (self, alg) {
            (TpmKeyType::EC(EcCurve::P256), JwsAlgorithm::ES256) => Ok(()),
            (key_type, alg) => Err(
                KeyStorageError::new(KeyStorageErrorKind::KeyAlgorithmMismatch)
                  .with_custom_message(format!("cannot use key type `{key_type:?}` with algorithm `{alg}`")),
              ),
        }
    }
}

impl Display for TpmKeyType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TpmKeyType::EC(EcCurve::P256) => f.write_str("P-256")
        }
    }
}

/// Supported curves for EC key objects
#[derive(Debug, Clone, Copy)]
pub enum EcCurve {
    P256
}

impl EcCurve {
    pub fn get_hashing_alg(&self) -> HashingAlgorithm {
        match self {
            EcCurve::P256 => HashingAlgorithm::Sha256,
        }
    }
}

impl TryInto<EccCurve> for EcCurve{
    type Error = TpmVaultError;

    fn try_into(self) -> Result<EccCurve, Self::Error> {
        match self {
            EcCurve::P256 => Ok(EccCurve::NistP256),
            //any => Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
        }
    }
}

