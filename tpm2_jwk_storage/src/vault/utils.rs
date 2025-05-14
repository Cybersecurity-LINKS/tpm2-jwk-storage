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

use sha2::{Digest, Sha256};
use tss_esapi::{constants::tss::TPM2_ALG_SHA256, interface_types::algorithm::HashingAlgorithm, structures::{HashScheme, Public, SignatureScheme}, traits::Marshall};

use super::error::TpmVaultError;

/// Compute an object name given a public object.
pub(crate) fn get_object_name(public: &Public) -> Result<Vec<u8>, TpmVaultError>{
    let serialized = public.marshall()?;

    match public.name_hashing_algorithm() {
        HashingAlgorithm::Sha256 => {
            Ok([
                &TPM2_ALG_SHA256.to_be_bytes(),
                Sha256::digest(serialized).as_slice()
            ].concat())
        }
        any => Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
    }
}

/// Compute the digest for a given signature scheme
pub (crate) fn digest(scheme: &SignatureScheme, message: &[u8]) -> Result<Vec<u8>, TpmVaultError>{

    let digest_scheme = match scheme {
        SignatureScheme::EcDsa { scheme: hash_scheme } => hash_scheme.hashing_algorithm(),
        any => return Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
    };

    match digest_scheme {
        HashingAlgorithm::Sha256 => Ok(Sha256::digest(message).to_vec()),
        any => return Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
    }
}

/// Retrieve the TPM object signature scheme from the JWK alg field
#[cfg(feature = "iota")]
pub(crate) fn get_signature_scheme_from_jwk(alg: &str) -> Result<SignatureScheme, TpmVaultError>{
    match alg {
        "ES256" => Ok(SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) }),
        any => Err(TpmVaultError::UnsupportedScheme(any.to_owned()))
    }
}