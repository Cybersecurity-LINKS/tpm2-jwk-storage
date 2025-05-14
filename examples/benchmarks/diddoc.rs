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

use std::{collections::VecDeque, time::{Duration, Instant}};

use examples::{write_to_csv, StorageType, TestName};
use identity_iota::{iota::NetworkName, storage::{KeyIdMemstore, Storage}};
use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};
use std::str::FromStr;

#[tokio::main]
async fn main() {
    // Setup phase:
    // Create a key storage
    let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    let storage = Storage::new(TpmVault::new(config), KeyIdMemstore::new());

    let mut results = VecDeque::<Duration>::with_capacity(100);

    // Benchmark execution
    for _ in 0..100{
      let start = Instant::now();
      // code to measure
      let (mut _document, _fragment) = examples::create_did_document(&NetworkName::try_from("network").expect("Network not valid"), &storage)
        .await;

      let elapsed = start.elapsed();
      results.push_front(elapsed);
    }

    // Benchmark completed: store results
    write_to_csv(TestName::CreateDidDoc, StorageType::Tpm, 0, 0, results);
}