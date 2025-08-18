use base64::Engine;
use base64::engine::general_purpose;
use ledger_signer::cli::run_cli;
use serde_json::json;
use std::io::Cursor;

mod ledger_manager;
use ledger_manager::LedgerManager;
use ledger_signer::{ledger, utils};

// first key in the hardcoded seed "abandon abandon abandon ..." given to the speculos emulator
fn first_key() -> serde_json::Value {
    json![{
        "key_id": utils::get_dervation_path(0),
        "public_key": {
            "Ed25519": "kAtNge7Oo98vdLFCAMT0zz9Jr6ynpjT/0s9v+Cva7PI="
        },
        "sui_address": "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"
    }]
}

#[tokio::test]
async fn test_cli_bad_method() {
    let _mgr = LedgerManager::acquire().await;
    let input = r#"{"jsonrpc":"2.0","method":"bad_method","params":{},"id":1}"#;
    let cursor = Cursor::new(input);
    let connection_type = ledger::ConnectionType::Tcp(9999);
    let result = run_cli(cursor, connection_type).await;

    assert!(result.is_err());
    let error = result.unwrap_err();
    assert!(error.0.to_string().contains("Invalid method: bad_method"));
}

#[tokio::test]
async fn test_cli_keys() {
    let _mgr = LedgerManager::acquire().await;
    let input = r#"{"jsonrpc":"2.0","method":"keys","params":{},"id":1}"#;
    let cursor = Cursor::new(input);
    let connection_type = ledger::ConnectionType::Tcp(9999);
    let result = run_cli(cursor, connection_type).await;

    assert!(result.is_ok());
    let response = result.unwrap();
    let response = response["result"].clone();
    let first_key = response["keys"][0].clone();

    assert_eq!(
        json![{
        "key_id": utils::get_dervation_path(0),
        "public_key": {
            "Ed25519": "kAtNge7Oo98vdLFCAMT0zz9Jr6ynpjT/0s9v+Cva7PI="
        },
        "sui_address": "0x5e93a736d04fbb25737aa40bee40171ef79f65fae833749e3c089fe7cc2161f1"}],
        first_key
    );

    assert!(response["keys"].is_array());
    assert!(response["keys"].as_array().unwrap().len() == 10);
}

#[tokio::test]
async fn test_cli_sign() {
    let mut mgr = LedgerManager::acquire().await;
    mgr.enable_blind_signing().await.unwrap();

    let message = "message";
    let message = general_purpose::STANDARD.encode(message);

    let input = Cursor::new(format!(
        r#"{{"jsonrpc":"2.0","method":"sign","params":{{"key_id":"{}","msg":"{}"}}, "id":1}}"#,
        utils::get_dervation_path(0),
        message
    ));
    let connection_type = ledger::ConnectionType::Tcp(9999);
    let (result, _) = tokio::join!(run_cli(input, connection_type), async {
        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        mgr.accept_transaction().await
    });

    assert!(result.is_ok());
    let response = result.unwrap();
    let response = response["result"].clone();
    assert!(response["signature"].is_string());
}

#[tokio::test]
async fn test_cli_get_public_key() {
    let _mgr = LedgerManager::acquire().await;
    let input = Cursor::new(format!(
        r#"{{"jsonrpc":"2.0","method":"public_key","params":{{"key_id":"{}"}}, "id":1}}"#,
        utils::get_dervation_path(0),
    ));

    let connection_type = ledger::ConnectionType::Tcp(9999);
    let result = run_cli(input, connection_type).await.unwrap();
    let result = result["result"].clone();

    assert_eq!(result, first_key());
}
