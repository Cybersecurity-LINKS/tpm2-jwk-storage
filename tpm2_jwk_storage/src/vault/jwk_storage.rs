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

use async_trait::async_trait;
use identity_iota::{storage::{JwkGenOutput, JwkStorage, KeyId, KeyStorageError, KeyStorageErrorKind, KeyStorageResult, KeyType}, verification::{jwk::Jwk, jws::JwsAlgorithm, jwu::{decode_b64, encode_b64}}};

use crate::types::{tpm_key_type::{EcCurve, TpmKeyType}, TpmKeyId};

use super::{tpm_vault::TpmVault, utils};

// Convert the KeyType into [TpmKeyType]
impl TryFrom<&KeyType> for TpmKeyType{
    type Error = KeyStorageError;
    
    fn try_from(value: &KeyType) -> Result<Self, Self::Error> {
        match value.as_str() {
            "P-256" => Ok(TpmKeyType::EC(EcCurve::P256)),
            _ => Err(KeyStorageError::new(KeyStorageErrorKind::UnsupportedKeyType))
        }
    }
}

// Implement the JwkStorage trait for TpmVault

#[async_trait(?Send)]
impl JwkStorage for TpmVault {
    /// Generate a new key represented as a JSON Web Key.
    ///
    /// It is recommended that the implementer exposes constants for the supported [`KeyType`].
    async fn generate(&self, key_type: KeyType, alg: JwsAlgorithm) -> KeyStorageResult<JwkGenOutput>{
        // check key type
        let key_type: TpmKeyType = (&key_type).try_into()?;
        key_type.check_key_alg_compatibility(&alg)?;

        // Generate a new keyId
        let key_id = self.random(32)
            .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::Unavailable).with_custom_message("Cannot retrieve a new key id"))?;
        let key_id = TpmKeyId::try_from(key_id)
            .map_err(|_| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_custom_message("Cannot convert random into key id"))?;

        // Create a new signing key
        let key = self.create_signing_key(key_type, &key_id)
            .map_err(|e| {KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e)})?;

        // Format the public key as a JWK
        let jwk = key.encode_jwk(&alg)
            .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::SerializationError).with_source(e))?;
        Ok(JwkGenOutput::new(KeyId::new(encode_b64(key_id)), jwk))
    }

    /// Insert an existing JSON Web Key into the storage.
    ///
    /// All private key components of the `jwk` must be set.
    /// ### Warning
    /// If called an Error is always returned.
    /// This method cannot be used inside the TPM. 
    /// Importing an external key inside the TPM is not supported.
    async fn insert(&self, _jwk: Jwk) -> KeyStorageResult<KeyId>{
        Err(KeyStorageError::new(KeyStorageErrorKind::Unavailable)
            .with_custom_message("Loading external keys is not supported"))
    }

    /// Sign the provided `data` using the private key identified by `key_id` according to the requirements of
    /// the corresponding `public_key` (see [`Jwk::alg`](Jwk::alg()) etc.).
    ///
    /// # Note
    ///
    /// High level methods from this library calling this method are designed to always pass a `public_key` that
    /// corresponds to `key_id` and additional checks for this in the `sign` implementation are normally not required.
    /// This is however based on the expectation that the key material associated with a given [`KeyId`] is immutable.  
    async fn sign(&self, key_id: &KeyId, data: &[u8], public_key: &Jwk) -> KeyStorageResult<Vec<u8>>{
        // Retrieve key id
        let key_id: [u8;32] = decode_b64(key_id.as_str())
            .ok()
            .and_then(|kid| kid.first_chunk::<32>().copied())
            .ok_or(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?;

        // Read required parameters from the JWK
        let alg = public_key.alg()
            .ok_or(KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm))?;
        let kid = public_key.kid()
            .and_then(|kid| decode_b64(kid).ok())
            .ok_or(KeyStorageError::new(KeyStorageErrorKind::Unspecified)
            .with_custom_message("Cannot read Jwk kid property"))?;
        // Convert JWK algorithm to signature scheme for the TPM
        let scheme = utils::get_signature_scheme_from_jwk(alg)
            .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::UnsupportedSignatureAlgorithm).with_source(e))?;

        self.tpm_sign(&key_id, data, &kid, scheme)
            .map(|signature| signature.value())
            .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::Unspecified).with_source(e))
    }

    /// Deletes the key identified by `key_id`.
    ///
    /// If the corresponding key does not exist in storage, a [`KeyStorageError`] with kind
    /// [`KeyNotFound`](crate::key_storage::KeyStorageErrorKind::KeyNotFound) must be returned.
    ///
    /// # Warning
    ///
    /// This operation cannot be undone. The keys are purged permanently.
    async fn delete(&self, key_id: &KeyId) -> KeyStorageResult<()>{
        let key_id: [u8;32] = decode_b64(key_id.as_str())
            .ok()
            .and_then(|kid| kid.first_chunk::<32>().copied())
            .ok_or(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?;
        self.tpm_delete(&key_id)
            .map_err(|e| KeyStorageError::new(KeyStorageErrorKind::KeyNotFound).with_source(e))
    }

    /// Returns `true` if the key with the given `key_id` exists in storage, `false` otherwise.
    async fn exists(&self, key_id: &KeyId) -> KeyStorageResult<bool>{
        let key_id: [u8;32] = decode_b64(key_id.as_str())
        .ok()
        .and_then(|kid| kid.first_chunk::<32>().copied())
        .ok_or(KeyStorageError::new(KeyStorageErrorKind::KeyNotFound))?;

        Ok(self.contains(&key_id))
    }

}