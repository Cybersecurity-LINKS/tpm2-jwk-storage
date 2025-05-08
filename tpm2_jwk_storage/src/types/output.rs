// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
 
//     http://www.apache.org/licenses/LICENSE-2.0
 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use tss_esapi::{structures::Name, utils::PublicKey};

/// Representation of a signing key.
/// 
/// It is a wrapper over the [PublicKey] and [Name] object
pub struct TpmSigningKey{
    public_key: PublicKey,
    name: Name
}

impl TpmSigningKey {
    pub fn new(public_key: PublicKey, name: Name) -> Self{
        TpmSigningKey{public_key, name}
    }
}