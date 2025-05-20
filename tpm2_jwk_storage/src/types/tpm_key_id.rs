// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
 
//     http://www.apache.org/licenses/LICENSE-2.0
 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(feature = "iota")]
use identity_iota::storage::KeyId;
use identity_iota::verification::jwu::encode_b64;


use crate::vault::error::TpmVaultError;

pub struct TpmKeyId {
    encoded: String,
    raw: [u8;32]
}

impl AsRef<[u8]> for TpmKeyId{
    fn as_ref(&self) -> &[u8] {
        &self.raw
    }
}

#[cfg(feature = "iota")]
impl TryFrom<KeyId> for TpmKeyId{
    type Error = TpmVaultError;

    fn try_from(value: KeyId) -> Result<Self, Self::Error> {
        use identity_iota::verification::jwu::decode_b64;

        decode_b64(value.as_str())
            .ok()
            .and_then(|kid| kid.first_chunk::<32>().copied())
            .ok_or(TpmVaultError::FormatError)
            .map(|decoded| Self{encoded: value.to_string(), raw: decoded})
    }
}

impl TryFrom<&[u8]> for TpmKeyId
{
    type Error = TpmVaultError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.first_chunk::<32>().copied()
            .ok_or(TpmVaultError::FormatError)
            .map(|decoded| Self{encoded: encode_b64(decoded), raw: decoded})
    }
}

impl From<[u8;32]> for TpmKeyId {
    fn from(value: [u8;32]) -> Self {
        Self { encoded: encode_b64(value), raw: value }
    }
}

impl AsRef<str> for TpmKeyId{
    fn as_ref(&self) -> &str {
        &self.encoded
    }
}

impl TpmKeyId{
    pub fn as_str(&self) -> &str{
        self.as_ref()
    }
}