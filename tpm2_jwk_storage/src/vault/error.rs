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

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TpmVaultError{
    #[error("The provided configuration is not correct: {0}")]
    TpmConfigError(String),
    #[cfg(feature = "tpm")]
    #[error("Connection to the TPM 2.0 failed. Reason: {0}")]
    ConnectionError(tss_esapi::Error),
    #[error(transparent)]
    TSSError(#[from] tss_esapi::Error),
    #[error("Bad input error for value {name} = {reason}. Reason: {reason}")]
    InputError{name: String, value: String, reason: String},
    #[error("The algorithm {0} is not supported")]
    UnsupportedAlgorithm(String),
    #[error("Key generation failed: {0}")]
    KeyGenError(tss_esapi::Error)
}