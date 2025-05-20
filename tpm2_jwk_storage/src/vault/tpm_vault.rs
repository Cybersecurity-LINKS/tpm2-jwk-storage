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

use tss_esapi::{abstraction::AsymmetricAlgorithmSelection, attributes::{ObjectAttributes, SessionAttributesBuilder}, constants::SessionType, handles::{AuthHandle, PersistentTpmHandle, SessionHandle, TpmHandle}, interface_types::{algorithm::{HashingAlgorithm, PublicAlgorithm}, ecc::EccCurve, reserved_handles::Hierarchy, session_handles::PolicySession}, structures::{Digest, EccParameter, EccPoint, EccScheme, HashScheme, Name, PublicBuilder, PublicEccParametersBuilder, SignatureScheme, SymmetricDefinition}, traits::Marshall, utils::PublicKey, Context};
use zeroize::Zeroizing;

use crate::types::{output::{TpmCacheRecord, TpmCredential, TpmSignature, TpmSigningKey}, tpm_key_id::TpmKeyId, tpm_key_type::{EcCurve, TpmKeyType}};

use super::{error::TpmVaultError, tpm_vault_config::TpmVaultConfig, utils::{self, get_object_name}};

type TpmObjectCache = HashMap<String, TpmCacheRecord>;
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
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    /// 
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id
    /// let key_id = vault.random(32).unwrap()
    ///     .try_into().unwrap();
    /// 
    /// // Create a new signing key and return public data
    /// let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id);
    /// ```
    pub fn create_signing_key(&self, key_type: TpmKeyType, key_id: &TpmKeyId) -> Result<TpmSigningKey, TpmVaultError>{

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
                let unique_parameter = EccParameter::from_bytes(key_id.as_ref())?;
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
       cache.insert(key_id.as_str().to_owned(), TpmCacheRecord::new(saved, primary.out_public.clone()));
       // Unlock
       drop(cache);

       // 4. Return the public key to the caller
       // Since the Public has been returned, the name is computed in software instead of using Esys_TR_GetName
       let name = get_object_name(&primary.out_public)
        .and_then(|name| Ok(Name::try_from(name)?))?;
       let public_key = PublicKey::try_from(primary.out_public)?;
       Ok(TpmSigningKey::new(public_key, name, key_type))
    }

    /// Create a digital signature with a signing key created by the TPM
    /// ### Inputs
    /// - `key_id`: [TpmKeyId] - The reference of the key to be used for signing
    /// - `payload`: &[u8] - Message to be signed
    /// ### Output
    /// Returns a [TpmSignature] if successful, [TpmVaultError] otherwise.
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    /// use tss_esapi::{interface_types::algorithm::HashingAlgorithm, structures::{Digest, HashScheme, SignatureScheme}};
    /// 
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id
    /// let key_id = b"deadbeefdeadbeefdeadbeefdeadbeef";
    /// let payload = b"foo";
    /// let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id).expect("Key not created");
    /// 
    /// let name = key.name();
    /// let scheme = SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) };
    /// // Create a new signing key and return public data
    /// let key = vault.tpm_sign(key_id, payload, &name, scheme);
    /// ```
    pub fn tpm_sign(&self, key_id: &TpmKeyId, payload: &[u8], name: &[u8], scheme: SignatureScheme) -> Result<TpmSignature, TpmVaultError>{

        // Try to read the requested key
        let cache = self.cache.read().unwrap(); // should never be in error state. Ok to panic
        let saved_key = cache.get(key_id.as_str())
            .ok_or(TpmVaultError::KeyNotFound)?
            .clone();
        drop(cache);

        // Create digest
        let digest = utils::digest(&scheme, payload)?;

        // Connect to the TPM and load the key
        let mut ctx = self.connect()?;
        let handle = ctx.context_load(saved_key.context())?;

        let signature = ctx.execute_with_nullauth_session(|context| {
            // Verify that the key is correct, checking the object name
            let obj_name = context.tr_get_name(handle)?;

            if name.ne(obj_name.value()){
                return Err(TpmVaultError::SignatureError("Name does not match".to_owned()));
            }

            // Sign with the loaded object
            Ok(context.sign(handle.into(), Digest::from_bytes(&digest)?, scheme, None)?)
        })?;

        Ok(TryInto::<TpmSignature>::try_into(signature)?)
    }

    /// Drop a key from the TPM vault. The key is removed from the in-memory cache of [TpmVault].
    /// ### Inputs
    /// - `key_id`: [TpmKeyId] - The reference of the key to be deleted
    /// ### Output
    /// Returns Ok(()) if successful, [TpmVaultError] otherwise.
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    ///
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id and a new signing key
    /// let key_id = b"deadbeefdeadbeefdeadbeefdeadbeef";
    /// vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id).unwrap();
    ///
    /// // Delete the signing key
    /// let key = vault.tpm_delete(&key_id);
    /// ```
    pub fn tpm_delete(&self, key_id: &TpmKeyId) -> Result<(), TpmVaultError>{
        // Try to read the requested key
        let mut cache = self.cache.write().unwrap(); // should never be in error state. Ok to panic
        cache.remove(key_id.as_str())
            .ok_or(TpmVaultError::KeyNotFound)?;
        Ok(())
    }

    /// Check if a signing key exists in the vault
    /// ### Inputs
    /// - `key_id`: [TpmKeyId] - The reference of the key to be checked
    /// ### Output
    /// Returns true if the key exists, false otherwise.
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    ///
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id and a new signing key
    /// let key_id = b"deadbeefdeadbeefdeadbeefdeadbeef";
    /// vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id).unwrap();
    ///
    /// // Check if the signing key exists
    /// let exists = vault.contains(&key_id);
    /// assert!(exists);
    /// // Delete the signing key
    /// vault.tpm_delete(&key_id).unwrap();
    /// // Check if the signing key exists
    /// let exists = vault.contains(&key_id);
    /// assert!(!exists);
    /// ```
    pub fn contains(&self, key_id: &TpmKeyId) -> bool{
        let cache = self.cache.read().unwrap(); // should never be in error state. Ok to panic
        cache.contains_key(key_id.as_str())
    }

    /// Retrieve the marshalled public template associated to a signing key
    /// ### Inputs
    /// - key_id: &[TpmKeyId] - The key identifier for the signing key
    /// ### Output
    /// An [Option<Vec<u8>>] containing a marshalled public template.
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    ///
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id and a new signing key
    /// let key_id = b"deadbeefdeadbeefdeadbeefdeadbeef";
    /// vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id).unwrap();
    ///
    /// // Check if the signing key exists
    /// let public = vault.get_public(&key_id);
    /// assert!(public.is_some());
    /// // Delete the signing key
    /// vault.tpm_delete(&key_id).unwrap();
    /// // Check if the signing key exists
    /// let public = vault.get_public(&key_id);
    /// assert!(public.is_none());
    /// ```
    pub fn get_public(&self, key_id: &TpmKeyId) -> Option<Vec<u8>>{
        let cache = self.cache.read().unwrap(); // should never be in error state. Ok to panic
        cache.get(key_id.as_str())
            .and_then(|rec| rec.public().marshall().ok())
    }
    /// Create a new Context using the configuration provided.
    fn connect(&self) -> Result<Context, TpmVaultError>{
        Context::new(self.config.clone())
            .map_err(|e| TpmVaultError::ConnectionError(e))
    }

    /*-------------------------
        CREDENTIAL PROTOCOL
     --------------------------*/
    /// Read the certificate of the Endorsement Key according to the [TCG EK Credential Profile](https://trustedcomputinggroup.org/wp-content/uploads/TCG-EK-Credential-Profile-for-TPM-Family-2.0-Level-0-Version-2.6_pub.pdf)
    /// ### Inputs
    /// - key_type: [TpmKeyType] - Endorsement Key Type
    /// ### Output
    /// DER encoded X.509 certificate, [TpmVaultError] otherwise
    /// ### Example
    /// ```rust
    /// use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
    /// use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
    /// use std::str::FromStr;
    ///
    /// // Create a new TpmVault, connecting to a TPM 2.0 device
    /// let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    /// let vault = TpmVault::new(config);
    /// // Create a new key_id and a new signing key
    /// let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), key_id).unwrap();
    ///
    /// // Delete the signing key
    /// vault.ek_certificate(TpmKeyType::EC(EcCurve::P256)).unwrap();
    /// ```
    pub fn ek_certificate(&self, key_type: TpmKeyType) -> Result<Vec<u8>, TpmVaultError>{
        let alg = match key_type {
            TpmKeyType::EC(EcCurve::P256) => AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256),
        };

        let mut ctx = self.connect()?;
        tss_esapi::abstraction::ek::retrieve_ek_pubcert(&mut ctx, alg)
            .map_err(|e| {e.into()})
    }

    pub fn activate_credential(&self, ek_handle: u32, credentialed_key: TpmKeyId, challenge: TpmCredential) -> Result<Zeroizing<Vec<u8>>, TpmVaultError>{
        // Retrieve the cached key
        let cache = self.cache.read()
            .expect("Unexpected failure");

        let key = cache.get(credentialed_key.as_str())
            .ok_or(TpmVaultError::KeyNotFound)
            .cloned()?;
        drop(cache);

        // Load required objects
        let ek_handle = TpmHandle::Persistent(PersistentTpmHandle::new(ek_handle)?);
        let mut ctx = self.connect()?;
        let key_handle = ctx.execute_with_nullauth_session(|context|
            context.context_load(key.context())    
        )?;
        let ek_handle = ctx.tr_from_tpm_public(ek_handle)?;

        // Generate a new authentication session to be used
        let session = ctx.start_auth_session(
            None, 
            None, 
            None, 
            SessionType::Hmac, 
            SymmetricDefinition::AES_128_CFB, 
            HashingAlgorithm::Sha256)?
            .ok_or(TpmVaultError::SessionError)?;

        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new()
        .with_decrypt(true)
        .with_encrypt(true)
        .build();
        ctx.tr_sess_set_attributes(session, session_attributes, session_attributes_mask)?;
        
        // Create policy auth session for EK
        let (session_attributes, session_attributes_mask) = SessionAttributesBuilder::new().build();
        let policy_auth_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(TpmVaultError::SessionError)?;

        ctx.tr_sess_set_attributes(policy_auth_session, session_attributes, session_attributes_mask)?;
        ctx.execute_with_nullauth_session(|context| {
            context.policy_secret(
                PolicySession::try_from(policy_auth_session)?,
                AuthHandle::Endorsement,
                Default::default(),
                Default::default(),
                Default::default(),
                None)
        })?;

        // execute activate credential to solve the challenge
        let secret = ctx.execute_with_sessions((Some(session), Some(policy_auth_session), None), |context|{
            let result = context.activate_credential(key_handle.clone().into(), ek_handle.into(), challenge.id_object(), challenge.encrypted_secret());
            result
        })
        .map(|digest| Zeroizing::new(digest.to_vec()))?;

        // Cleanup
        ctx.flush_context(SessionHandle::from(session).into())?;
        ctx.flush_context(SessionHandle::from(policy_auth_session).into())?;

        Ok(secret)
    }
}

#[cfg(test)]
mod tests{
    use tss_esapi::{interface_types::algorithm::HashingAlgorithm, structures::{Digest, HashScheme, SignatureScheme}};

    use crate::{types::{tpm_key_id::TpmKeyId, tpm_key_type::{EcCurve, TpmKeyType}}, vault::{error::TpmVaultError, tpm_vault_config::TpmVaultConfig}};
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
        let id = TpmKeyId::try_from(random.as_slice()).unwrap();
        let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), &id);
        assert!(key.is_ok());
    }

    #[test]
    fn test_100_keygen(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);

        for i in 0..100 {
            let random = vault.random(32).unwrap();
            let id = TpmKeyId::try_from(random.as_slice()).unwrap();

            let key = vault.create_signing_key(TpmKeyType::EC(EcCurve::P256), &id);
            assert!(key.is_ok());
            println!("Iter {i} OK!")
        }
    }

    #[test]
    fn test_sign(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(32).unwrap();
        let id = TpmKeyId::try_from(random.as_slice()).unwrap();

        let key = vault
            .create_signing_key(TpmKeyType::EC(EcCurve::P256), &id)
            .unwrap();
        let id = TpmKeyId::try_from(random.as_slice()).unwrap();

        let name = key.name();
        let scheme= SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) };
        let signature = vault.tpm_sign(&id, b"foo", &name, scheme).unwrap();

        let signature = signature.as_slice();
        println!("{signature:?}");
    }

    #[test]
    fn test_sign_no_keys(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(32).unwrap();
        let id = TpmKeyId::try_from(random.as_slice()).unwrap();

        let scheme= SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) };

        let signature = vault.tpm_sign(&id, b"foo", &random, scheme);
        assert_eq!(signature.err(), Some(TpmVaultError::KeyNotFound))
    }

    #[test]
    fn test_100_sign(){
        let config = TpmVaultConfig::from_str("tabrmd").unwrap();
        let vault = TpmVault::new(config);
        let random = vault.random(32).unwrap();
        let id = TpmKeyId::try_from(random.as_slice()).unwrap();

        let key = vault
            .create_signing_key(TpmKeyType::EC(EcCurve::P256), &id)
            .unwrap();
        let name = key.name();
        let scheme= SignatureScheme::EcDsa { scheme: HashScheme::new(HashingAlgorithm::Sha256) };

        for i in 0..100{
            let signature = vault.tpm_sign(&id, b"foo", &name, scheme);
            assert!(signature.is_ok());
            println!("Iter {i} OK!")
        }
    }
}