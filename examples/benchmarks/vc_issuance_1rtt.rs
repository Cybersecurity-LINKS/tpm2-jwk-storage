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

use examples::{create_did, dtos::EncryptedCredentialResponse, API_ENDPOINT};
use identity_iota::{storage::{KeyIdMemstore, KeyIdStorage, KeyType, MethodDigest, Storage}, verification::jwu::decode_b64};
use iota_sdk::client::{secret::{mnemonic::MnemonicSecretManager, SecretManager}, Client};
use reqwest::multipart::{self, Part};
use tpm2_jwk_storage::{types::{tpm_key_type::{EcCurve, TpmKeyType}, TpmKeyId}, vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig}};
use std::{collections::VecDeque, str::FromStr, time::{Duration, Instant}};

#[tokio::main]
async fn main(){
    let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None)
    .expect("Client configuration failed")
    .finish()
    .await
    .expect("Connection failed");

    let mut mnemonic = Client::generate_mnemonic()
        .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
        .expect("Cannot create new secret manager");
    let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    let storage = Storage::new(TpmVault::new(config), KeyIdMemstore::new());
    let mut results = VecDeque::<Duration>::with_capacity(100);
    let vault = storage.key_storage();

    let (_, document, _) = create_did(&client, &mut mnemonic, &storage).await
        .expect("Publish did failed");
    let did = document.id().to_string();
    let mut tx: usize = 0;
    let mut rx: usize = 0;

    for _ in (0..100){
        tx = 0;
        rx = 0;

        let client = reqwest::ClientBuilder::new().build().expect("Cannot use http client");
        let start = Instant::now();

        let certificate = vault.ek_certificate(TpmKeyType::EC(EcCurve::P256)).expect("Failed to retrieve certificate");
        tx += certificate.len();

        let holder_vm = document.methods(None)[0];
        let holder_key_id = storage
            .key_id_storage()
            .get_key_id(&MethodDigest::new(&holder_vm).expect("Incorrect verification method"))
            .await
            .expect("Cannot retrieve the key identifier");
        let tpm_key_id = decode_b64(holder_key_id.as_str()).expect("key identifier format NOK");
        let tpm_key_id = TpmKeyId::try_from(tpm_key_id).expect("key identifier format NOK");
        let marshalled_public = vault.get_public(&tpm_key_id)
            .expect("Public not found");

        tx += marshalled_public.len();
        tx += did.as_bytes().len();
        tx = tx + b"ek_cert".len() + b"tpm_key_pub".len() + b"did".len();

        let form = multipart::Form::new()
            .part("ek_cert", Part::bytes(certificate))
            .part("tpm_key_pub", Part::bytes(marshalled_public))
            .text("did", did.to_owned());

        let response = client.get("http://127.0.0.1:3213/api/make_credential/complete")
            .multipart(form)
            .send()
            .await
            .expect("Client failed")
            .error_for_status()
            .expect("Response error")
            .bytes().await
            .expect("Serialization error");

        rx += response.len();

        let response = serde_json::from_slice::<EncryptedCredentialResponse>(&response)
            .expect("Challenge serialization errror");

        let id_obj = decode_b64(response.id_object).expect("Cannot decode the challlenge");
        let enc_sec = decode_b64(response.enc_secret).expect("Cannot decode the challlenge");

    }
}