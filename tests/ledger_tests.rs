/*
Warning these tests require a running emulator or ledger device.
*/
use base64::{Engine as _, engine::general_purpose};
use ledger_signer::{
    ledger::{get_public_key, get_tcp_connection, sign_transaction},
    utils::get_dervation_path,
};

mod ledger_manager;
use ledger_manager::LedgerManager;

#[tokio::test]
async fn test_get_test_connection() {
    let _mgr = LedgerManager::acquire().await;

    // This test is for demonstration purposes only
    // In practice, you would use a mock or a real Ledger device
    let result = get_tcp_connection(9999).await;
    assert!(
        result.is_ok(),
        "Failed to get test connection: {:?}",
        result.err()
    );
}

#[tokio::test]
async fn test_get_public_key() {
    let _mgr = LedgerManager::acquire().await;

    let mut connection = get_tcp_connection(9999).await.unwrap();
    let derivation_path = get_dervation_path(0);
    let public_key = get_public_key(&derivation_path, &mut connection.0).await;
    assert!(
        public_key.is_ok(),
        "Failed to get public key: {:?}",
        public_key.err()
    );
}

#[tokio::test]
async fn test_sign_transaction() {
    let mut mgr = LedgerManager::acquire().await;

    mgr.enable_blind_signing().await.unwrap();

    let connection = get_tcp_connection(9999).await.unwrap();
    let derivation_path = get_dervation_path(0);

    let message = "message";
    let message = general_purpose::STANDARD.encode(message);

    let (signature_result, ledger_mgr_result) = tokio::join!(
        sign_transaction(derivation_path, &message, connection),
        async {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            mgr.accept_transaction().await
        }
    );
    ledger_mgr_result.expect("Failed to accept transaction");
    let signature = signature_result
        .expect("Failed to sign transaction")
        .signature;
    assert!(!signature.is_empty(), "Signature should not be empty");
}

#[tokio::test]
async fn test_enable_blind_signing() {
    let mut mgr = LedgerManager::acquire().await;
    // This test assumes the emulator is running and the app is open
    mgr.enable_blind_signing()
        .await
        .expect("Failed to enable blind signing");
}

#[tokio::test]
async fn test_go_home() {
    let mgr = LedgerManager::acquire().await;
    mgr.go_home().await.expect("Failed to go home");
}
