//! Integration tests for P-256 signature verification
//!
//! These tests verify that P-256 public keys can verify signatures,
//! which is the primary use case for WebAuthn/passkey support.
use multicodec::Codec;
use multikey::{Builder, Views};
use multiutil::CodecInfo;

#[test]
fn test_p256_public_key_from_ssh() {
    // Test that we can import a P-256 public key from SSH format
    // This is how we'd import a passkey public key from WebAuthn registration
    // once the caller has extracted it from the attestation object and converted
    // it from COSE to SSH format (0x04 || X || Y)

    let mut rng = rand_core_6::OsRng;

    // Generate a test P-256 keypair via SSH
    let keypair =
        ssh_key::private::EcdsaKeypair::random(&mut rng, ssh_key::EcdsaCurve::NistP256).unwrap();

    let private_key = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ecdsa(keypair),
        "test p256 key",
    )
    .unwrap();

    let public_key_ssh = private_key.public_key();

    // Import the public key into multikey (simulates WebAuthn registration)
    let public_key = Builder::new_from_ssh_public_key(public_key_ssh)
        .unwrap()
        .try_build()
        .unwrap();

    assert_eq!(public_key.codec(), Codec::P256Pub);
    assert!(public_key.attr_view().unwrap().is_public_key());
    assert!(!public_key.attr_view().unwrap().is_secret_key());
}

#[test]
fn test_p256_signature_verification() {
    // Test end-to-end signature verification
    // Simulates: passkey signs data (via SSH key infrastructure), we verify with stored public key

    let mut rng = rand_core_6::OsRng;

    // Create a P-256 keypair using SSH infrastructure (simulating passkey)
    let keypair =
        ssh_key::private::EcdsaKeypair::random(&mut rng, ssh_key::EcdsaCurve::NistP256).unwrap();

    let private_key_ssh = ssh_key::PrivateKey::new(
        ssh_key::private::KeypairData::Ecdsa(keypair),
        "test passkey",
    )
    .unwrap();

    // Import private key to multikey (we have this from SSH)
    let secret_key = Builder::new_from_ssh_private_key(&private_key_ssh)
        .unwrap()
        .try_build()
        .unwrap();

    // Derive public key (this is what we'd store from WebAuthn registration)
    let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();

    // Data to sign (e.g., authentication challenge)
    let challenge = b"authenticate this challenge";

    // Sign using built-in signing (simulates WebAuthn assertion creation)
    let signature = secret_key
        .sign_view()
        .unwrap()
        .sign(challenge, false, None)
        .unwrap();

    let result = public_key
        .verify_view()
        .unwrap()
        .verify(&signature, Some(challenge));

    assert!(result.is_ok(), "Signature verification should succeed");
}

#[test]
fn test_p256_verification_fails_wrong_message() {
    // Verify that verification correctly fails with wrong message

    let mut rng = rand_core_6::OsRng;

    // Create keypair via SSH
    let keypair =
        ssh_key::private::EcdsaKeypair::random(&mut rng, ssh_key::EcdsaCurve::NistP256).unwrap();

    let private_key_ssh =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ecdsa(keypair), "test").unwrap();

    let secret_key = Builder::new_from_ssh_private_key(&private_key_ssh)
        .unwrap()
        .try_build()
        .unwrap();

    let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();

    let original_message = b"original message";
    let wrong_message = b"wrong message";

    // Create signature for original message
    let signature = secret_key
        .sign_view()
        .unwrap()
        .sign(original_message, false, None)
        .unwrap();

    // Verification should fail with wrong message
    let result = public_key
        .verify_view()
        .unwrap()
        .verify(&signature, Some(wrong_message));

    assert!(
        result.is_err(),
        "Verification should fail with wrong message"
    );
}

#[test]
fn test_p256_combined_signature() {
    // Test combined signatures (message included in signature)

    let mut rng = rand_core_6::OsRng;

    let keypair =
        ssh_key::private::EcdsaKeypair::random(&mut rng, ssh_key::EcdsaCurve::NistP256).unwrap();

    let private_key_ssh =
        ssh_key::PrivateKey::new(ssh_key::private::KeypairData::Ecdsa(keypair), "test").unwrap();

    let secret_key = Builder::new_from_ssh_private_key(&private_key_ssh)
        .unwrap()
        .try_build()
        .unwrap();

    let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();

    let message = b"combined signature test";

    // Create combined signature (message embedded)
    let signature = secret_key
        .sign_view()
        .unwrap()
        .sign(message, true, None)
        .unwrap();

    assert!(
        !signature.message.is_empty(),
        "Combined signature should contain message"
    );

    // Verify without providing message (it's in the signature)
    let result = public_key.verify_view().unwrap().verify(&signature, None);

    assert!(
        result.is_ok(),
        "Combined signature verification should succeed"
    );
}

#[test]
fn test_p256_public_key_fingerprint() {
    // Test that we can fingerprint P-256 public keys
    // Useful for key identification

    let mut rng = rand_core_6::OsRng;

    let secret_key = Builder::new_from_random_bytes(Codec::P256Priv, &mut rng)
        .unwrap()
        .try_build()
        .unwrap();

    let public_key = secret_key.conv_view().unwrap().to_public_key().unwrap();

    // Get SHA-256 fingerprint
    let fingerprint = public_key
        .fingerprint_view()
        .unwrap()
        .fingerprint(Codec::Sha2256)
        .unwrap();

    let digest_bytes: Vec<u8> = fingerprint.into();
    assert!(!digest_bytes.is_empty());
}
