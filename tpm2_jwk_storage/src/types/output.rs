// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
 
//     http://www.apache.org/licenses/LICENSE-2.0
 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::ops::Deref;
use tss_esapi::{structures::{Name, Public, SavedTpmContext, Signature}, utils::PublicKey};

use crate::vault::error::TpmVaultError;

use super::{tpm_key_type::TpmKeyType};

#[cfg(feature = "iota")]
use identity_iota::verification::jws::JwsAlgorithm;        
#[cfg(feature = "iota")]
use identity_iota::verification::jwk::Jwk;

/// Representation of a signing key.
/// 
/// It is a wrapper over the [PublicKey] and [Name] object
pub struct TpmSigningKey{
    public_key: PublicKey,
    name: Name,
    key_type: TpmKeyType
}

impl TpmSigningKey {
    pub fn new(public_key: PublicKey, name: Name, key_type: TpmKeyType) -> Self{
        TpmSigningKey{public_key, name, key_type}
    }

    pub fn name(&self) -> Vec<u8>{
        self.name.value().to_vec()
    }

    #[cfg(feature = "iota")]
    pub (crate) fn encode_jwk(&self, alg: &JwsAlgorithm) -> Result<Jwk, TpmVaultError>{
        use std::any::Any;

        use identity_iota::verification::{jwk::JwkParamsEc, jwu::encode_b64};

        let mut jwk = match &self.public_key {
            PublicKey::Ecc { x, y } => {
                let mut params = JwkParamsEc::new();
                params.x = encode_b64(x);
                params.y = encode_b64(y);
                params.crv = self.key_type.to_string();
                Jwk::from_params(params)
            },
            pubkey => return Err(TpmVaultError::UnsupportedKeyType(format!("{:?}", pubkey.type_id())))
        };

        jwk.set_kid(encode_b64(self.name.value())); 
        jwk.set_alg(alg.name());

        jwk.to_public()
        .ok_or(TpmVaultError::FormatError)
    }
}

/// Struct to contain cached objects in the TPM vault.
/// 
/// It contains a [SavedTpmContext] and its [Public] representation for better performances
#[derive(Debug, Clone)]
pub(crate) struct TpmCacheRecord{
    ctx: SavedTpmContext,
    public: Public
}

impl TpmCacheRecord {
    pub(crate) fn new(ctx: SavedTpmContext, public: Public) -> Self {
        TpmCacheRecord{ctx, public}
    }

    pub(crate) fn context(&self) -> SavedTpmContext{
        self.ctx.clone()
    }

    pub(crate) fn public(&self) -> Public {
        self.public.clone()
    }
}

/// Digital signature representation of a 
pub struct TpmSignature(Vec<u8>);

impl TryFrom<Signature> for TpmSignature{
    type Error = TpmVaultError;

    fn try_from(value: Signature) -> Result<Self, Self::Error> {
        match value {
            Signature::EcDsa(sig) => Ok(TpmSignature(
                [sig.signature_r().as_bytes(), 
                sig.signature_s().as_bytes()]
                .concat().to_vec())),
            any => Err(TpmVaultError::UnsupportedAlgorithm(format!("{any:?}")))
        }
    }
}

impl Deref for TpmSignature{
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl TpmSignature{
    pub(crate) fn value(&self) -> Vec<u8>{
        self.0.clone()
    }
}