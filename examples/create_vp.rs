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
use identity_eddsa_verifier::EdDSAJwsVerifier;
use identity_iota::{core::{Duration, FromJson, Object, Timestamp, Url}, credential::{Credential, CredentialBuilder, DecodedJwtCredential, DecodedJwtPresentation, FailFast, Jwt, JwtCredentialValidationOptions, JwtCredentialValidator, JwtCredentialValidatorUtils, JwtPresentationOptions, JwtPresentationValidationOptions, JwtPresentationValidator, JwtPresentationValidatorUtils, Presentation, PresentationBuilder, Subject, SubjectHolderRelationship}, did::{CoreDID, DIDUrl, DID}, document::verifiable::JwsVerificationOptions, iota::IotaDocument, prelude::Resolver, storage::{JwkDocumentExt, JwkMemStore, JwsSignatureOptions, KeyIdMemstore, KeyIdStorage, KeyType, MethodDigest, Storage}, verification::{jws::JwsAlgorithm, jwu::{decode_b64, encode_b64}, MethodScope}};
use iota_sdk::{client::{secret::SecretManager, Client}, types::block::address::Address};
use serde_json::json;
use sha2::{Digest, Sha256};
use tpm2_jwk_storage::{types::{tpm_key_type::{EcCurve, TpmKeyType}, tpm_key_id::TpmKeyId}, vault::{tpm_vault::TpmVault, tpm_vault_config::TpmVaultConfig}};
use std::{collections::HashMap, str::FromStr};
use identity_ecdsa_verifier::EcDSAJwsVerifier;

#[tokio::main]
async fn main(){
    // Setup the IOTA client
    let client: Client = Client::builder()
        .with_primary_node(API_ENDPOINT, None)
        .expect("Client configuration failed")
        .finish()
        .await
        .expect("Client connection failed");

    let mut secret_manager_issuer = Client::generate_mnemonic()
    .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
    .expect("Cannot create new secret manager");

    // Use the in-memory storage to store issuer keys
    let storage_issuer = Storage::new(JwkMemStore::new(), KeyIdMemstore::new());
    // Issuer Identity
    let (_, issuer_document, fragment_issuer): (Address, IotaDocument, String) = create_did(&client, &mut secret_manager_issuer, &storage_issuer, KeyType::new("Ed25519"), JwsAlgorithm::EdDSA).await
    .expect("Did publish: operation failed");

    let mut secret_manager_holder = Client::generate_mnemonic()
        .and_then(|mnemonic| SecretManager::try_from_mnemonic(mnemonic))
        .expect("Cannot create new secret manager");

    let config = TpmVaultConfig::from_str("tabrmd")
        .expect("TPM Vault configuration not valid");
    let vault = TpmVault::new(config);
    // Create a key storage for the holder using the TPM Vault
    let storage_holder = Storage::new(vault, KeyIdMemstore::new());
    let vault = storage_holder.key_storage();

    // Holder identity
    let (_, holder_document, fragment_holder): (Address, IotaDocument, String) =
    examples::create_did(&client, &mut secret_manager_holder, &storage_holder, KeyType::new("P-256"), JwsAlgorithm::ES256).await
        .expect("Did publish: operation failed");

    let _ek_certificate = vault.ek_certificate(TpmKeyType::EC(EcCurve::P256))
        .expect("Cannot read EK certificate");

    let mut vm_address = DIDUrl::new(holder_document.id().clone().into(), None);
    vm_address
        .set_fragment(Some(&fragment_holder))
        .expect("bad did url");
    let vm = holder_document.resolve_method(vm_address, Some(MethodScope::VerificationMethod))
        .and_then(|method| MethodDigest::new(method).ok())
        .expect("Verification method digest not computed");
    let holder_key_id = storage_holder.key_id_storage()
        .get_key_id(&vm)
        .await
        .ok()
        .and_then(|key_id| TpmKeyId::try_from(key_id).ok())
        .expect("Key id not found");

    let key_public_object = vault.get_public(&holder_key_id).expect("Public not found");

    /* Holder -> Issuer sends: 
    - X.509 certificate of the EK
    - Marshalled public template of the key to verify 
    - DID of the holder (the holder document MUST be resolved by the issuer)
    */

    /*
        The issuer should verify the EK certificate. If the certificate is not valid, the VC issuance should fail
    */

    /*
        The issuer needs to validate the public template as well, in order to check that the TPM object satisfies the desired policy.
        For instance, in order to have a key that cannot be exported outside of the TPM, the object attributes should be:
        - fixedTpm
        - fixedParent
        - sign (constraint to use the object only for digital signatures)
     */
    examples::check_public_attributes(&key_public_object)
        .expect("Key validation failed");


    // Set the subject
    let jwk = holder_document.methods(None)[0].data().public_key_jwk().expect("Not a jwk");
    let kid = jwk.kid()
        .and_then(|name| decode_b64(name).ok())
        .expect("Cannot decode key identifier from jwk");

    let parameters = jwk.try_ec_params().ok()
        .expect("Cannot find parameters");

    let x = decode_b64(parameters.x.as_bytes()).expect("Cannot decode jwk ec parameters");
    let y = decode_b64(parameters.y.as_bytes()).expect("Cannot decode jwk ec parameters");
    
    // check name
    examples::check_public_key(&key_public_object, &kid, &x, &y)
        .expect("Key verification failed");

    let subject = Subject::from_json_value(
        json!({
            "id": holder_document.id().as_str(),
            "sha256": encode_b64(Sha256::digest([x,y].concat()))
        })
    )
    .expect("Cannot create the subject");

    let credential: Credential = CredentialBuilder::default()
    .id(Url::parse("https://example.com/1234").expect("Bad URL"))
    .issuer(Url::parse(issuer_document.id().as_str()).expect("Bad DID"))
    .type_("TpmCredential")
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
    let expires: Timestamp = Timestamp::now_utc().checked_add(Duration::minutes(10))
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
    let holder: IotaDocument = resolver.resolve(&holder_did).await
        .expect("Did resolve failed");
    let presentation_verifier_options: JwsVerificationOptions =
        JwsVerificationOptions::default().nonce(nonce.to_owned());

    let presentation_validation_options = JwtPresentationValidationOptions::default()
        .presentation_verifier_options(presentation_verifier_options);
    let presentation: DecodedJwtPresentation<Jwt> = JwtPresentationValidator::with_signature_verifier(EcDSAJwsVerifier::default(),)
        .validate(&presentation_jwt, &holder, &presentation_validation_options)
        .expect("Presentation validation failed");
    
    let jwt_credentials: &Vec<Jwt> = &presentation.presentation.verifiable_credential;
    let issuers: Vec<CoreDID> = jwt_credentials
    .iter()
    .map(JwtCredentialValidatorUtils::extract_issuer_from_jwt)
    .collect::<Result<Vec<CoreDID>, _>>()
    .expect("Cannot find VC issuers");
    let issuers_documents: HashMap<CoreDID, IotaDocument> = resolver
        .resolve_multiple(&issuers).await
        .expect("Issuer documents not resolved");

    let credential_validator: JwtCredentialValidator<EdDSAJwsVerifier> =
        JwtCredentialValidator::with_signature_verifier(EdDSAJwsVerifier::default());
    let validation_options: JwtCredentialValidationOptions = JwtCredentialValidationOptions::default()
        .subject_holder_relationship(holder_did.to_url().into(), SubjectHolderRelationship::AlwaysSubject);

  for (index, jwt_vc) in jwt_credentials.iter().enumerate() {
    // SAFETY: Indexing should be fine since we extracted the DID from each credential and resolved it.
    let issuer_document: &IotaDocument = &issuers_documents[&issuers[index]];

    let _decoded_credential: DecodedJwtCredential<Object> = credential_validator
      .validate::<_, Object>(jwt_vc, issuer_document, &validation_options, FailFast::FirstError)
      .unwrap();

    if _decoded_credential.credential.types.contains(&String::from_str("TpmCredential").unwrap()) {
        // if the type is TpmCredential I can check the signing key
        let digest = _decoded_credential.credential.credential_subject[0].properties.get("sha256")
            .expect("Key digest not found")
            .as_str()
            .expect("Digest not found");

        let jwk = holder.methods(None)[0].data().public_key_jwk()
            .expect("Jwk not found")
            .try_ec_params()
            .expect("EC params not found");

        let x = decode_b64(jwk.x.clone()).expect("Decode error");
        let y = decode_b64(jwk.y.clone()).expect("Decode error");

        let computed = Sha256::digest([x,y].concat());

        assert_eq!(encode_b64(computed), digest)

    }
  }

  println!("VP successfully validated: {:#?}", presentation);
}