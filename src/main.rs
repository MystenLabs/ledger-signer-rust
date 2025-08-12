pub mod constants;
pub mod device;
pub mod errors;
pub mod ledger;
pub mod path;
pub mod types;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::io::{self, Write};
use std::panic;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignArgs {
    pub key_id: String,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Key {
    pub public_key: String,
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeysResponse {
    pub keys: Vec<Key>,
}

#[tokio::main]
pub async fn main() {
    panic::set_hook(Box::new(|info| {
        let payload = if let Some(payload) = info.payload().downcast_ref::<String>().or(info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .as_ref())
        {
            // If the payload is a String, use it directly
            payload.clone()
        } else {
            // Otherwise, use a default message
            "unknown panic".to_string()
        };

        let location = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown location".to_string());

        let json = json!({
            "error": {
                "code": 1,
                "message": "Panic occurred",
                "data": {
                    "payload": payload,
                    "location": location,
                }
            },
        });

        let _ = writeln!(io::stdout(), "{json}");
    }));

    if std::env::args().nth(1).as_deref() == Some("call") {
        let JsonRpcRequest {
            jsonrpc: _,
            method,
            params,
            id: _,
        } = read_json_line().expect("Unable to deserialize request");

        if method.is_empty() {
            return return_error("method is required");
        }

        match method.as_str() {
            "create_key" => {
                return_error("create_key command is not implemented yet");
            }
            "sign_hashed" => {
                return_error("sign_hashed command is not supported");
            }
            "sign" => {
                let connection = ledger::get_connection().await.unwrap();
                let args = serde_json::from_value::<SignArgs>(params)
                    .expect("Failed to parse sign_hashed arguments");
                if args.key_id.is_empty() {
                    return_error("key id is required");
                } else if args.msg.is_empty() {
                    return_error("base64 encoded message to sign is required");
                } else {
                    ledger::sign_transaction(args.key_id, args.msg, connection)
                        .await
                        .expect("Failed to sign transaction");
                }
            }
            "keys" => {
                let mut connection = ledger::get_connection().await.unwrap();
                let mut keys = vec![];
                for i in 0..5 {
                    let derivation_path = get_dervation_path(i);

                    keys.push(Key {
                        public_key: ledger::get_public_key(&derivation_path, &mut connection.0)
                            .await
                            .expect("Failed to get public key")
                            .public_key,
                        key_id: derivation_path,
                    })
                }

                let response = KeysResponse { keys };
                let json_response =
                    serde_json::to_string(&response).expect("Failed to serialize keys response");
                println!("{json_response}");
            }
            _ => {
                return_error("invalid method");
            }
        }
    } else {
        eprintln!("This script is meant to be called with 'call' as the first argument");
        std::process::exit(1);
    }
}

fn return_error(message: &str) {
    let error_response = json!({
        "error": {
            "code": 1,
            "message": message,
        },
    });
    println!("{error_response}");
}

pub fn get_dervation_path(index: u32) -> String {
    // 44'/784'/0'/0'/0'
    format!("44'/784'/0'/0'/{index}'")
}

pub fn read_json_line() -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}
