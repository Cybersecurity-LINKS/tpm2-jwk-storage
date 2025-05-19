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
use examples::dtos::{EncryptedCredentialResponse, NonceResponse};
use examples::{create_did, write_to_csv, StorageType, TestName, API_ENDPOINT, EK_HANDLE, VERIFIER_BASE_URL};
use identity_iota::core::{Timestamp, ToJson};
use identity_iota::credential::{Jwt, JwtPresentationOptions, Presentation, PresentationBuilder};
use identity_iota::did::DID;
use identity_iota::storage::{JwkDocumentExt, JwsSignatureOptions, KeyIdMemstore, KeyIdStorage, KeyType, MethodDigest, Storage};
use identity_iota::verification::jws::JwsAlgorithm;
use identity_iota::verification::jwu::decode_b64;
use iota_sdk::client::{secret::SecretManager, Client};
use josekit::jwe::alg::direct::DirectJweAlgorithm::Dir;
use reqwest::multipart::{self, Part};
use serde_json::json;
use tpm2_jwk_storage::types::output::TpmCredential;
use tpm2_jwk_storage::types::tpm_key_type::{EcCurve, TpmKeyType};
use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};

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
    let vault = storage.key_storage();

    let (_, document, fragment) = create_did(&client, &mut mnemonic, &storage, KeyType::new("P-256"), JwsAlgorithm::ES256).await
        .expect("Publish did failed");
    let did = document.id().to_string();

    let mut results_vp_created = VecDeque::<Duration>::with_capacity(100);
    let mut results_vp_finished = VecDeque::<Duration>::with_capacity(100);

    let certificate = vault.ek_certificate(TpmKeyType::EC(EcCurve::P256)).expect("Failed to retrieve certificate");

    let holder_vm = document.methods(None)[0];
    let holder_key_id = storage
        .key_id_storage()
        .get_key_id(&MethodDigest::new(&holder_vm).expect("Incorrect verification method"))
        .await
        .expect("Cannot retrieve the key identifier");
    let tpm_key_id = holder_key_id.try_into().expect("key identifier format NOK");
    let marshalled_public = vault.get_public(&tpm_key_id)
        .expect("Public not found");

    let form = multipart::Form::new()
        .part("ek_cert", Part::bytes(certificate))
        .part("tpm_key_pub", Part::bytes(marshalled_public))
        .text("did", did.to_owned());
    
    let client = reqwest::ClientBuilder::new().build().expect("Cannot use http client");
    let response = client.get("http://127.0.0.1:3213/api/make_credential/complete")
        .multipart(form)
        .send()
        .await
        .expect("Client failed")
        .error_for_status()
        .expect("Response error")
        .bytes().await
        .expect("Serialization error");
    
    let response = serde_json::from_slice::<EncryptedCredentialResponse>(&response)
        .expect("Challenge serialization error");

    let id_obj = decode_b64(response.id_object).expect("Cannot decode the challenge");
    let enc_sec = decode_b64(response.enc_secret).expect("Cannot decode the challenge");

    let challenge = TpmCredential::new(&id_obj, &enc_sec)
        .expect("Bad format for challenge");

    // Solve the challenge
    let credential_encryption_key = vault.activate_credential(EK_HANDLE, tpm_key_id, challenge)
        .expect("Activate credential failed");
    
    let decrypter = Dir.decrypter_from_bytes(&credential_encryption_key)
        .expect("Cannot create decrypter");

    let (payload, _header) = josekit::jwt::decode_with_decrypter(response.enc_jwt.expect("JWE not found"), &decrypter)
        .expect("Decryption failed");
    let vc_jwt = payload.claim("vc_jwt")
        .expect("Verifiable Credential not found in the JWT");

    let mut tx: usize = 0;
    let mut rx: usize = 0;
    for _ in 0..100 {
        rx = 0;
        tx = 0;
        let start = Instant::now();

        let expires: Timestamp = Timestamp::now_utc().checked_add(identity_iota::core::Duration::minutes(10)).unwrap();
        //create a new presentation starting from the VC
        let presentation: Presentation<Jwt> = PresentationBuilder::new(document.id().to_url().into(), Default::default())
            .credential(Jwt::from(vc_jwt.to_string()))
            .build()
            .expect("Cannot create the Verifiable Presentation");

        let nonce = client.get(format!("{}/challenges", VERIFIER_BASE_URL))
            .send().await
            .expect("Client failed")
            .bytes().await
            .expect("Serialization error");
        
        let nonce = serde_json::from_slice::<NonceResponse>(&nonce)
            .expect("Cannot read nonce");
        
        let presentation_jwt = document
        .create_presentation_jwt(
            &presentation,
            &storage, 
            &fragment, 
            &JwsSignatureOptions::default().nonce(nonce.nonce.clone()), 
            &JwtPresentationOptions::default().expiration_date(expires))
        .await
        .expect("Verifiable presentation creation failed");

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
        results_vp_finished.push_front(elapsed);
    }
    
    // Benchmark completed: store results
    write_to_csv(TestName::VPCreate, StorageType::Tpm, tx, rx, results_vp_created);
    write_to_csv(TestName::VPFinish, StorageType::Tpm, tx, rx, results_vp_finished);
}