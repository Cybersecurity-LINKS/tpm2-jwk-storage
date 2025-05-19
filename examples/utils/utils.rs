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

use std::{borrow::Cow, collections::VecDeque, error::Error, fmt::Display, fs::create_dir_all, time::Duration};

use identity_iota::{iota::{IotaClientExt, IotaDocument, IotaIdentityClientExt, NetworkName}, storage::{JwkDocumentExt, JwkStorage, KeyIdStorage, KeyType, Storage}, verification::{jws::JwsAlgorithm, MethodScope}};
use iota_sdk::{client::{api::GetAddressesOptions, node_api::indexer::query_parameters::QueryParameter, secret::SecretManager, Client}, types::block::{address::{Address, Bech32Address, Hrp}, output::AliasOutput}};
use serde::{Deserialize, Serialize};

pub mod dtos;

//pub static API_ENDPOINT: &str = "https://api.testnet.shimmer.network";
//pub static FAUCET_ENDPOINT: &str = "https://faucet.testnet.shimmer.network/api/enqueue";

//pub static API_ENDPOINT: &str = "https://stardust.linksfoundation.com/node1";
//pub static FAUCET_ENDPOINT: &str = "https://stardust.linksfoundation.com/faucet/l1/api/enqueue";

pub static API_ENDPOINT: &str = "https://api.testnet.iotaledger.net";
pub static FAUCET_ENDPOINT: &str = "https://faucet.testnet.iotaledger.net/api/enqueue";

pub const ISSUER_BASE_URL: &str = "http://127.0.0.1:3213/api";
pub const VERIFIER_BASE_URL: &str = "http://127.0.0.1:3214/api";
/// Persistent handle where the EK has been loaded before the execution.
/// This address can be arbitrarily decided within the range of addresses for the Endorsement Hierarchy
pub const EK_HANDLE: u32 = 0x81010001;

const TPM_SHA_256_ID: u16 = 0x000B;

#[derive(Debug)]
pub struct UtilsError<'a>(Cow<'a, str>);

impl<'a> Display for UtilsError<'a>{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'a> std::error::Error for UtilsError<'a>{}

#[derive(Debug, Serialize, Deserialize)]
pub struct BenchmarkMeasurement{
    test_name: TestName,
    storage_type: StorageType,
    duration: Duration,
    tx: usize,
    rx: usize
}

impl BenchmarkMeasurement{
    pub fn new(test_name: TestName, storage_type: StorageType, duration: Duration, tx: usize, rx: usize) -> BenchmarkMeasurement{
    BenchmarkMeasurement {test_name, storage_type, duration, tx, rx}
    }

    pub fn as_row(&self) -> [String; 5]{
        [self.test_name.to_string(), self.storage_type.to_string(), self.duration.as_nanos().to_string(), self.tx.to_string(), self.rx.to_string()]
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TestName{
    Keygen,
    CreateDidDoc,
    VcIssuance,
    VcIssuanceComplete,
    VPCreate,
    VPFinish
}

impl Display for TestName{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{:?}", self)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum StorageType{
    Memstore,
    Stronghold,
    Tpm
}

impl Display for StorageType{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f,"{:?}", self)
    }
}

pub fn write_to_csv(name: TestName, storage: StorageType, tx: usize, rx: usize, measures: VecDeque<Duration>){
    let test_name = &name.to_string().to_lowercase();
    create_dir_all(format!("results/{test_name}")).expect("Cannot create a directory");
    let mut csv = csv::WriterBuilder::new()
      .from_path(format!("results/{}/{}.csv", test_name, storage.to_string().to_ascii_lowercase())).expect("Cannot create file");
    measures
      .iter()
      .map(|time| {BenchmarkMeasurement::new(name.clone(), storage.clone(), *time, tx, rx)})
      .for_each(|record| { csv.write_record(&record.as_row()).unwrap();});
  }

pub async fn create_did_document(
    network: &NetworkName,
  storage: &Storage<impl JwkStorage, impl KeyIdStorage>,
  key_type: KeyType,
  alg: JwsAlgorithm
) -> (IotaDocument, String) 
  {
  let mut document: IotaDocument = IotaDocument::new(network);

  let fragment: String = document
    .generate_method(
        storage,
        key_type,
        alg,
        None,
        MethodScope::VerificationMethod,
    )
    .await
    .expect("Document not created");
  (document, fragment)
}

pub async fn get_address(client: &Client, secret_manager: &SecretManager) -> Result<Bech32Address, Box<dyn Error>> {

  let bech32_hrp: Hrp = client.get_bech32_hrp().await?;
  let address: Bech32Address = secret_manager
    .generate_ed25519_addresses(
      GetAddressesOptions::default()
        .with_range(0..1)
        .with_bech32_hrp(bech32_hrp),
    )
    .await?[0];

  Ok(address)
}

async fn get_address_balance(client: &Client, address: &Bech32Address) -> Result<u64, Box<dyn Error>> {
  let output_ids = client
    .basic_output_ids(vec![
      QueryParameter::Address(address.to_owned()),
      QueryParameter::HasExpiration(false),
      QueryParameter::HasTimelock(false),
      QueryParameter::HasStorageDepositReturn(false),
    ])
    .await
    .expect("Output not generated");

  let outputs = client.get_outputs(&output_ids).await?;

  let mut total_amount = 0;
  for output_response in outputs {
    total_amount += output_response.output().amount();
  }

  Ok(total_amount)
}

/// Requests funds from the faucet for the given `address`.
async fn request_faucet_funds(client: &Client, address: Bech32Address, faucet_endpoint: &str) -> Result<(), Box<dyn Error>> {
  iota_sdk::client::request_funds_from_faucet(faucet_endpoint, &address).await?;

  tokio::time::timeout(std::time::Duration::from_secs(45), async {
    loop {
      tokio::time::sleep(std::time::Duration::from_secs(5)).await;

      let balance = get_address_balance(client, &address)
        .await?;
      if balance > 0 {
        break;
      }
    }
    Ok::<(), Box<dyn Error>>(())
  })
  .await
  .map_err(|_| UtilsError(Cow::Borrowed("Timeout")))??;

  Ok(())
}

pub async fn get_address_with_funds(
  client: &Client,
  stronghold: &SecretManager,
  faucet_endpoint: &str,
) -> Result<Address, Box<dyn Error>> {
  let address: Bech32Address = get_address(client, stronghold).await?;

  request_faucet_funds(client, address, faucet_endpoint)
    .await
    .map_err(|_| Cow::Borrowed("failed to request faucet funds"))?;

  Ok(*address)
}

pub async fn create_did(
  client: &Client,
  secret_manager: &mut SecretManager,
  storage: &Storage<impl JwkStorage, impl KeyIdStorage>,
  key_type: KeyType,
  alg: JwsAlgorithm
) -> Result<(Address, IotaDocument, String), Box<dyn Error>> {
  let address: Address = crate::get_address_with_funds(client, secret_manager, crate::FAUCET_ENDPOINT)
    .await
    .map_err(|_| Cow::Borrowed("failed to get address with funds"))?;

  let network_name: NetworkName = client.network_name().await?;

  let (document, fragment): (IotaDocument, String) = create_did_document(&network_name, storage, key_type, alg).await;

  let alias_output: AliasOutput = client.new_did_output(address, document, None).await?;

  let document: IotaDocument = client.publish_did_output(secret_manager, alias_output).await?;

  Ok((address, document, fragment))
}

/// check attributes of a TPM object.
/// Ensure that the received object has the attributes:
/// - sign
/// - fixedTpm
/// - fixedParent
#[cfg(feature = "tpm")]
pub fn check_public_attributes(marshalled: &[u8]) -> Result<(), &'static str>{
    use tss_esapi::{structures::Public, traits::UnMarshall};

    // unmarshall
    let public = Public::unmarshall(marshalled);

    let attributes = match public {
        Ok(public) => public.object_attributes(),
        Err(_) => return Err("Unmarshalling failed")
    };

    if attributes.fixed_parent() &&
        attributes.fixed_parent() &&
        attributes.sign_encrypt(){
            Ok(())
    }
    else {
        Err("Attributes' validation failed")
    }
}

/// Compute the object name from the marshalled public. 
/// Only SHA-256 names supported for testing purposes
#[cfg(feature = "tpm")]
pub fn get_name_from_public(marshalled: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    [&TPM_SHA_256_ID.to_be_bytes(), Sha256::digest(marshalled).as_slice()].concat()
}

/// Check if the tpm object corresponds to an EC public key
#[cfg(feature = "tpm")]
pub fn check_public_key(marshalled: &[u8], name: &[u8], x: &[u8], y: &[u8]) -> Result<(), &'static str>{
    use tss_esapi::{structures::Public, traits::UnMarshall};

    let computed_name = get_name_from_public(marshalled);

    if computed_name.ne(name){
        return Err("Computed name does not match");
    }
    
    let public = Public::unmarshall(marshalled)
        .map_err(|_| "Cannot serialize public")?;

    match public {
        Public::Ecc { object_attributes: _, name_hashing_algorithm: _, auth_policy: _, parameters: _, unique } => {
            if unique.x().as_bytes().ne(x) ||
                unique.y().as_bytes().ne(y){
                    return Err("Public key does not match");
                }

        },
        _ => unimplemented!("Not supported")
    }
    Ok(())
}