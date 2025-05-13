use std::any::Any;

use sha2::{Digest, Sha256};
use tss_esapi::{constants::tss::TPM2_ALG_SHA256, interface_types::algorithm::{EccSchemeAlgorithm, HashingAlgorithm}, structures::{EccScheme, HashScheme, Public, SignatureScheme}, traits::Marshall};

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

/// Retrieve the signature scheme associated to a public object
pub(crate) fn get_signature_scheme(public: &Public) -> Result<tss_esapi::structures::SignatureScheme, TpmVaultError> {
    if let Public::Ecc { object_attributes: _, name_hashing_algorithm: _, auth_policy: _, parameters, unique: _ } = public {
        
        let scheme = parameters.ecc_scheme().algorithm();


        let hash_scheme = match parameters.ecc_scheme() {
            EccScheme::EcDsa(scheme) => scheme,
            any => return Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
        };

        match scheme {
            EccSchemeAlgorithm::EcDsa => Ok(SignatureScheme::EcDsa { scheme: hash_scheme }),
            any => return Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
        }
    }
    else {
        Err(TpmVaultError::InputError { name: "public".to_owned(),
            value: format!("{:?}", 
            public.type_id()), 
            reason: "Unsupported public type".to_owned() })
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