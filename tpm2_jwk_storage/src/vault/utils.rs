use sha2::{Digest, Sha256};
use tss_esapi::{constants::tss::TPM2_ALG_SHA256, interface_types::algorithm::HashingAlgorithm, structures::Public, traits::Marshall};

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