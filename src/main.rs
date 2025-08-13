pub mod constants;
pub mod device;
pub mod errors;
pub mod ledger;
pub mod path;
pub mod types;

use anyhow::anyhow;
use ledger_signer::utils::get_dervation_path;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io::{BufRead, Write, stdin, stdout};
use std::{io, panic};

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
    let reader = stdin();
    set_panic_hook();
    let buf_reader = io::BufReader::new(reader);
    match run_cli(buf_reader).await {
        Ok(result) => println!("{}", serde_json::to_string(&result).unwrap()),
        Err(e) => {
            return_error(&e.to_string());
        }
    }
}

pub fn set_panic_hook() {
    panic::set_hook(Box::new(move |info| {
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

        let _ = writeln!(stdout(), "{json}");
    }));
}

pub async fn run_cli<R: BufRead>(buf_reader: R) -> Result<Value, anyhow::Error> {
    if std::env::args().nth(1).as_deref() == Some("call") {
        let JsonRpcRequest {
            jsonrpc: _,
            method,
            params,
            id: _,
        } = read_json_line(buf_reader).expect("Unable to deserialize request");

        if method.is_empty() {
            return Err(anyhow::anyhow!("Method is required"));
        }

        match method.as_str() {
            "create_key" => Err(anyhow!("create_key command is not implemented yet")),
            "sign_hashed" => Err(anyhow!("sign_hashed command is not supported")),
            "sign" => {
                let connection = ledger::get_connection().await.unwrap();
                let args = serde_json::from_value::<SignArgs>(params)
                    .expect("Failed to parse sign_hashed arguments");
                if args.key_id.is_empty() {
                    Err(anyhow!("key id is required"))
                } else if args.msg.is_empty() {
                    Err(anyhow!("base64 encoded message to sign is required"))
                } else {
                    Ok(serde_json::to_value(
                        ledger::sign_transaction(args.key_id, &args.msg, connection).await?,
                    )?)
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
                Ok(serde_json::to_value(KeysResponse { keys })?)
            }
            _ => Err(anyhow!("Invalid method: {}", method)),
        }
    } else {
        eprintln!("This script is meant to be called with 'call' as the first argument");
        std::process::exit(1);
    }
}

fn return_error(message: &str) {
    println!(
        "{}",
        json!({
            "error": {
                "code": 1,
                "message": message,
            },
        })
    );
}

pub fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader.read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}
