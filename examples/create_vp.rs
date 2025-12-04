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

use examples::{create_did, API_ENDPOINT};
use identity_ecdsa_verifier::EcDSAJwsVerifier;
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{
    core::{Duration, FromJson, Object, Timestamp, Url},
    credential::{
        Credential, CredentialBuilder, DecodedJwtCredential, DecodedJwtPresentation, FailFast, Jwt,
        JwtCredentialValidationOptions, JwtCredentialValidator, JwtCredentialValidatorUtils,
        JwtPresentationOptions, JwtPresentationValidationOptions, JwtPresentationValidator,
        JwtPresentationValidatorUtils, Presentation, PresentationBuilder, Subject,
        SubjectHolderRelationship,
    },
    did::{CoreDID, DIDUrl, DID},
    document::verifiable::JwsVerificationOptions,
    iota::IotaDocument,
    prelude::Resolver,
    storage::{JwkDocumentExt, JwkMemStore, JwsSignatureOptions, KeyIdMemstore, KeyType, Storage},
    verification::jws::JwsAlgorithm,
};
use iota_sdk::{
    client::{secret::SecretManager, Client},
    types::block::address::Address,
};
use serde_json::json;
use std::{collections::HashMap, str::FromStr};
use tpm2_jwk_storage::vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig};

/*
   This example simulates the phases required to implement the trust triangle. The process has been customized to exploit TPM unique functionalities.
   It proceeds as follows:
   1. Holder requests a Verifiable Credential to a credential Issuer
   2. The Issuer verifies the identity of the requester through a cryptographic challange. It can only be solved by a unique TPM device.
   3. The Holder solves the challenge and receives a Verifiable Credential from the Issuer
   4. The Holder includes the VC in a Verifiable Presentation and it sends it to the Verifier
   5. The Verifier receives holder's VP and check presentation authenticity and credential validity
*/
#[tokio::main]
async fn main() {
    env_logger::init();
    // Setup the IOTA client
    let client: Client = Client::builder()
        .with_primary_node(API_ENDPOINT, None)
        .expect("Client configuration failed")
        .finish()
        .await
        .expect("Client connection failed");

    // Create an in memory secret manager for the issuer
    let mut secret_manager_issuer = Client::generate_mnemonic()
        .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
        .expect("Cannot create new secret manager");

    // Use the in-memory storage to store issuer keys
    let storage_issuer = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
    // Issuer publish a new DID on the configured network
    let (_, issuer_document, fragment_issuer): (Address, IotaDocument, String) = create_did(
        &client,
        &mut secret_manager_issuer,
        &storage_issuer,
        KeyType::new("Ed25519"),
        JwsAlgorithm::EdDSA,
    )
    .await
    .expect("Did publish: operation failed");

    // Create an in memory secret manager for the holder
    let mut secret_manager_holder = Client::generate_mnemonic()
        .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
        .expect("Cannot create new secret manager");

    // Configure the TpmVault for the holder
    let config =
        TpmVaultConfig::from_str("device:/dev/tpmrm0").expect("TPM Vault configuration not valid");
    let vault = TpmVault::new(config);
    // Create a key storage for the holder using the TpmVault
    let storage_holder = Storage::new(vault, KeyIdMemstore::new());

    // Holder publish a new DID on the configured network
    let (_, holder_document, fragment_holder): (Address, IotaDocument, String) =
        examples::create_did(
            &client,
            &mut secret_manager_holder,
            &storage_holder,
            KeyType::new("P-256"),
            JwsAlgorithm::ES256,
        )
        .await
        .expect("Did publish: operation failed");

    // Retrieve the public template of the signing key generated during DID document publication
    let mut vm_address = DIDUrl::new(holder_document.id().clone().into(), None);
    vm_address
        .set_fragment(Some(&fragment_holder))
        .expect("Bad did url");

    // Credential issuance by the issuer
    let subject = Subject::from_json_value(json!({
        "id": holder_document.id().as_str()
    }))
    .expect("Cannot create the subject");

    let credential: Credential = CredentialBuilder::default()
        .id(Url::parse("https://example.com/1234").expect("Bad URL"))
        .issuer(Url::parse(issuer_document.id().as_str()).expect("Bad DID"))
        .subject(subject)
        .build()
        .expect("Issuer cannot create a Verifiable Credential");

    // Issuer signs the credential
    let credential_jwt: Jwt = issuer_document
        .create_credential_jwt(
            &credential,
            &storage_issuer,
            &fragment_issuer,
            &JwsSignatureOptions::default(),
            None,
        )
        .await
        .expect("VC: Issuer signature failed");

    // Issuer -> Holder sends the Verifiable Credential. The Holder stores the VC.

    // Holder creates a new VP that includes the VC. Receive a nonce from the Verifier
    let nonce = "yI1v5eVv9T+EeMTGZUVaP7I/tdDoM2i+ctBcyhJgZgg=";
    let expires: Timestamp = Timestamp::now_utc()
        .checked_add(Duration::minutes(10))
        .expect("Expiration not valid");

    // Create and sign a new Verifiable Presentation
    let presentation: Presentation<Jwt> =
        PresentationBuilder::new(holder_document.id().to_url().into(), Default::default())
            .credential(credential_jwt)
            .build()
            .expect("Presentation build failed");

    let presentation_jwt: Jwt = holder_document
        .create_presentation_jwt(
            &presentation,
            &storage_holder,
            &fragment_holder,
            &JwsSignatureOptions::default().nonce(nonce),
            &JwtPresentationOptions::default().expiration_date(expires),
        )
        .await
        .expect("Cannot sign the presentation");

    // Holder -> Verifier sends the presentation as a JWT
    let mut resolver: Resolver<IotaDocument> = Resolver::new();
    resolver.attach_iota_handler(client);

    // Verifier verifies the VP
    let holder_did: CoreDID = JwtPresentationValidatorUtils::extract_holder(&presentation_jwt)
        .expect("Holder DID not found");
    let holder: IotaDocument = resolver
        .resolve(&holder_did)
        .await
        .expect("Did resolve failed");
    let presentation_verifier_options: JwsVerificationOptions =
        JwsVerificationOptions::default().nonce(nonce.to_owned());

    let presentation_validation_options = JwtPresentationValidationOptions::default()
        .presentation_verifier_options(presentation_verifier_options);
    let presentation: DecodedJwtPresentation<Jwt> =
        JwtPresentationValidator::with_signature_verifier(EcDSAJwsVerifier::default())
            .validate(&presentation_jwt, &holder, &presentation_validation_options)
            .expect("Presentation validation failed");

    println!("VP signature verified");

    // Validate the list of verifiable credentials
    let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
    let issuers: Vec<CoreDID> = jwt_credentials
        .iter()
        .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
        .collect::<Result<Vec<CoreDID>, _>>()
        .expect("Cannot find VC issuers");
    let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver
        .resolve_multiple(&issuers)
        .await
        .expect("Issuer documents not resolved");

    let credential_validator: JwtCredentialValidator<EdDSAJwsVerifier> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    let validation_options: JwtCredentialValidationOptions =
        JwtCredentialValidationOptions::default().subject_holder_relationship(
            holder_did.to_url().into(),
            SubjectHolderRelationship::AlwaysSubject,
        );

    for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
        let issuer_document: &IotaDocument = &issuers_documents[&issuers[index]];

        let _decoded_credential: DecodedJwtCredential<Object> = credential_validator
            .validate::<_, Object>(
                jwt_vc,
                issuer_document,
                &validation_options,
                FailFast::FirstError,
            )
            .unwrap();
    }

    println!("VP successfully validated: {:#?}", presentation);
}
