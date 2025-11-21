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

use std::time::Instant;
use std::{collections::VecDeque, time::Duration};
use std::str::FromStr;
use examples::dtos::{CredentialReponse, NonceResponse, SimpleCredentialRequestDTO};
use examples::{create_did, write_to_csv, StorageType, TestName, API_ENDPOINT, VERIFIER_BASE_URL};
use identity_iota::core::{Timestamp, ToJson};
use identity_iota::credential::{Jwt, JwtPresentationOptions, Presentation, PresentationBuilder};
use identity_iota::did::DID;
use identity_iota::storage::{JwkDocumentExt, JwsSignatureOptions, KeyIdMemstore, KeyType, Storage};
use identity_iota::verification::jws::JwsAlgorithm;
use iota_sdk::client::{secret::SecretManager, Client};
use serde_json::json;
use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};

#[tokio::main]
async fn main(){

    env_logger::builder().filter_level(log::LevelFilter::Debug).init();

    let client: Client = Client::builder()
    .with_primary_node(API_ENDPOINT, None)
    .expect("Client configuration failed")
    .finish()
    .await
    .expect("Connection failed");

    // Create the wallet for DID publication
    let mut mnemonic = Client::generate_mnemonic()
        .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
        .expect("Cannot create new secret manager");

    // Create TPM storage
    let config = TpmVaultConfig::from_str("tabrmd").unwrap();
    let storage = Storage::new(TpmVault::new(config), KeyIdMemstore::new());

    // DID publication
    let (_, document, fragment) = create_did(&client, &mut mnemonic, &storage, KeyType::new("P-256"), JwsAlgorithm::ES256).await
        .expect("Publish did failed");
    let did = document.id().to_string();

    let mut results_vp_created = VecDeque::<Duration>::with_capacity(100);
    let mut results_vp_sign = VecDeque::<Duration>::with_capacity(100);
    let mut results_vp_finished = VecDeque::<Duration>::with_capacity(100);
    
    // VC request to the issuer
    let client = reqwest::ClientBuilder::new().build().expect("Cannot use http client");
    let response = client.get(format!("http://127.0.0.1:3213/api/challenges?did={did}"))
        .send()
        .await
        .expect("Client failed")
        .error_for_status()
        .expect("Response error")
        .bytes().await
        .expect("Serialization error");
    
    let response = serde_json::from_slice::<NonceResponse>(&response)
        .expect("Challenge serialization error");

    // Sign the nonce challenge
    let signature = document.create_jws(
        &storage, 
        &fragment, 
        response.nonce.as_bytes(),
        &JwsSignatureOptions::default().nonce(&response.nonce))
        .await
        .expect("Cannot sign JWS");
    
    let request_body = SimpleCredentialRequestDTO{
        did: did,
        nonce: response.nonce,
        identity_signature: signature.as_str().to_string()
    };
    let response = client.post("http://127.0.0.1:3213/api/credentials/iota")
        .json::<SimpleCredentialRequestDTO>(&request_body)
        .send()
        .await
        .expect("Responce error during credential negotiation")
        .json::<CredentialReponse>()
        .await
        .expect("Parsing error");
    let vc_jwt = response.vc_jwt;

    let mut tx: usize = 0;
    let mut rx: usize = 0;
    for _ in 0..100 {
        rx = 0;
        tx = 0;
        let start = Instant::now();

        let expires: Timestamp = Timestamp::now_utc().checked_add(identity_iota::core::Duration::minutes(10)).unwrap();
        //create a new presentation starting from the VC
        let presentation: Presentation<Jwt> = PresentationBuilder::new(document.id().to_url().into(), Default::default())
            .credential(Jwt::from(vc_jwt.clone()))
            .build()
            .expect("Cannot create the Verifiable Presentation");

        let nonce = client.get(format!("{}/challenges", VERIFIER_BASE_URL))
            .send().await
            .expect("Client failed")
            .bytes().await
            .expect("Serialization error");
        
        let nonce = serde_json::from_slice::<NonceResponse>(&nonce)
            .expect("Cannot read nonce");
        
        let before_sign = start.elapsed();
        let presentation_jwt = document
        .create_presentation_jwt(
            &presentation,
            &storage, 
            &fragment, 
            &JwsSignatureOptions::default().nonce(nonce.nonce.clone()), 
            &JwtPresentationOptions::default().expiration_date(expires))
        .await
        .expect("Verifiable presentation creation failed");
        let after_sign = start.elapsed();

        let vp_created_duration = start.elapsed();
        let start = Instant::now();
        let request = json!({"nonce": nonce.nonce.clone(), "presentation": String::from(presentation_jwt)});
        tx += request.to_json().unwrap().len();

        let _ = client.post(format!("{}/verify/iota", VERIFIER_BASE_URL))
            .json(&request)
            .send().await
            .expect("Client failure")
            .error_for_status()
            .expect("Response error");
        let elapsed = start.elapsed();
        results_vp_created.push_front(vp_created_duration);
        results_vp_sign.push_front(after_sign-before_sign);
        results_vp_finished.push_front(elapsed);
    }
    
    // Benchmark completed: store results
    write_to_csv(TestName::VPCreate, StorageType::Tpm, tx, rx, results_vp_created);
    write_to_csv(TestName::VPSign, StorageType::Tpm, tx, rx, results_vp_sign);
    write_to_csv(TestName::VPFinish, StorageType::Tpm, tx, rx, results_vp_finished);
}