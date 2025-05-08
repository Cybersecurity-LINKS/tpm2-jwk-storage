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

use std::{collections::HashMap, sync::RwLock};

use tss_esapi::{attributes::ObjectAttributes, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm}, reserved_handles::Hierarchy}, structures::{Digest, EccParameter, EccPoint, EccScheme, HashScheme, Name, PublicBuilder, PublicEccParametersBuilder, SavedTpmContext}, utils::PublicKey, Context};

use crate::types::{output::TpmSigningKey, tpm_key_type::TpmKeyType, TpmKeyId};

use super::{error::TpmVaultError, tpm_vault_config::TpmVaultConfig, utils::get_object_name};

type TpmObjectCache = HashMap<TpmKeyId, SavedTpmContext>;
/// Performs key management operations using TSS 2.0 ESAPI wrapper.
/// 
/// It tries to connect to the TPM 2.0 pointed by the provided configuration
pub struct TpmVault{
    //ctx: Mutex<Context>,
    //session: Arc<Option<AuthSession>>,
    /// Tpm configuration used for connection
    config: TpmVaultConfig,
    cache: RwLock<TpmObjectCache>
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
        let cache = RwLock::new(TpmObjectCache::new());
        TpmVault { config, cache }
    }

    /// Retrieve random bytes from the TPM TRNG
    /// ### Input
    /// * `size` [usize] - Number of random bytes to generate
    /// 
    /// ### Output
    /// [Vec<u8>] containing random bytes
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
        // check that requested size is in the correct range
        if size > Digest::MAX_SIZE {
            return Err(TpmVaultError::InputError { name: "size".to_owned(),
                value: size.to_string(), 
                reason: format!("Random size cannot exceed {0}", Digest::MAX_SIZE) })
        }
        let mut ctx = self.connect()?;
        let random = ctx.get_random(size)?;

        Ok(random.to_vec())
    } 


    /// Create a new identity key using the TPM.
    /// 
    /// It generates a new key TPM object with a supported algorithm specified in [TpmKeyType].
    /// The key object is fixed to the device and cannot be exported. In addition, it can only perform digital signatures.
    /// The object uses the key_id as `unique_data` in order to enable deterministic key derivation.
    /// 
    /// ### Inputs
    /// - key_type: [TpmKeyType] - key type to be generated
    /// - key_id: [TpmKeyId] - 32 bytes long used as `unique_data`
    /// ### Output
    /// If the execution is successful, a [TpmSigningKeyResult] is returned.
    /// Otherwise, a [TpmVaultError] is returned.
    pub fn create_signing_key(&self, key_type: TpmKeyType, key_id: TpmKeyId) -> Result<TpmSigningKey, TpmVaultError>{

       // 1. Build the public template
       let attributes =  ObjectAttributes::new_fixed_signing_key();
       let mut builder = PublicBuilder::new();
       builder = builder
       .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
       .with_object_attributes(attributes);

       // Set the parameters of the key based on the key type
       match key_type {
           TpmKeyType::EC(curve) => {
                let ec_curve = curve.try_into()?;
                let hashing_alg = (&curve).get_hashing_alg();
                let ec_param = PublicEccParametersBuilder::new_unrestricted_signing_key(
                    EccScheme::EcDsa(HashScheme::new(hashing_alg)), ec_curve).build()?;
                let unique_parameter = EccParameter::from_bytes(&key_id)?;
                builder = builder.with_ecc_parameters(ec_param)
                    .with_ecc_unique_identifier(EccPoint::new(unique_parameter.clone(), unique_parameter))
                    .with_public_algorithm(PublicAlgorithm::Ecc);
           }
       }

       let public_template = builder.build()?;

       // 2. Create the Primary Key Object on the TPM
       let mut ctx = self.connect()?;
       let primary = ctx.execute_with_nullauth_session(|context|{
            context.create_primary(Hierarchy::Owner, public_template, None, None, None, None)
       })?;

       // 3. Export the context and save in the in-memory cache
       let saved = ctx.context_save(primary.key_handle.into())?;

       let mut cache = self.cache.write().unwrap(); // should never be in error state. Ok to panic
       cache.insert(key_id, saved);
       // Unlock
       drop(cache);

       // 4. Return the public key to the caller
       // Since the Public has been returned, the name is computed in software instead of using Esys_TR_GetName
       let name = get_object_name(&primary.out_public)
        .and_then(|name| Ok(Name::try_from(name)?))?;
       let public_key = PublicKey::try_from(primary.out_public)?;
       Ok(TpmSigningKey::new(public_key, name))
    }

    /// Create a new Context using the configuration provided.
    fn connect(&self) -> Result<Context, TpmVaultError>{
        Context::new(self.config.clone())
            .map_err(|e| TpmVaultError::ConnectionError(e))
    }
}

#[cfg(test)]
mod tests{
    use tss_esapi::structures::Digest;

    use crate::{types::tpm_key_type::{EcCurve, TpmKeyType}, vault::{error::TpmVaultError, tpm_vault_config::TpmVaultConfig}};
    use std::str::FromStr;

    use super::TpmVault;

    #[test]
    fn test_random(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(32);
        
        assert!(random.is_ok());
        let random = random.unwrap();
        assert_eq!(random.len(), 32)
    }

    #[test]
    fn test_too_big_random(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(1024);

        assert!(random.is_err());
        assert_eq!(random.err(), Some(TpmVaultError::InputError { name: "size".to_owned(),
            value: 1024.to_string(), 
            reason: format!("Random size cannot exceed {0}", Digest::MAX_SIZE) }))
    }


    #[test]
    fn test_keygen(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(32).unwrap();
        let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), random.try_into().unwrap());

        assert!(key.is_ok())
    }
}