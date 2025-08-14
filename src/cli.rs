use crate::ledger;
use crate::ledger::LedgerConnection;
use crate::types::*;
use crate::utils::get_dervation_path;
use anyhow::anyhow;
use serde_json::{Value, json};
use std::{
    io::{BufRead, Write, stdout},
    panic,
};

pub fn set_panic_hook(id: u64) {
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
            "jsonrpc": "2.0",
            "error": {
                "code": 1,
                "message": format!("Panic occurred: {}", payload),
                "data": {
                    "payload": payload,
                    "location": location,
                }
            },
            "id": id,
        });

        let _ = writeln!(stdout(), "{json}");
    }));
}

pub fn check_subcommand() {
    if std::env::args().nth(1).as_deref() != Some("call") {
        return_error("Invalid subcommand. Use 'call' to invoke the CLI.", 0);
        std::process::exit(1);
    }
}

pub async fn run_cli<R: BufRead>(
    buf_reader: R,
    ledger_conn: LedgerConnection,
) -> Result<Value, (anyhow::Error, u64)> {
    let JsonRpcRequest {
        jsonrpc: _,
        method,
        params,
        id,
    } = read_json_line(buf_reader).expect("Unable to deserialize request");

    if method.is_empty() {
        return Err((anyhow::anyhow!("Method is required"), id));
    }

    Ok(serde_json::to_value(JsonRpcResponse {
        jsonrpc: "2.0".to_string(),
        result: handle_request(&method, params, ledger_conn)
            .await
            .map_err(|e| (e, id))?,
        id,
    })
    .map_err(|e| (anyhow::anyhow!("Failed to serialize response: {}", e), id))?)
}

pub async fn handle_request(
    method: &str,
    params: Value,
    mut ledger_conn: LedgerConnection,
) -> Result<Value, anyhow::Error> {
    match method {
        "create_key" => Err(anyhow!("create_key command is not implemented yet")),
        "sign_hashed" => Err(anyhow!("sign_hashed command is not supported")),
        "sign" => {
            let args = serde_json::from_value::<SignArgs>(params)
                .expect("Failed to parse sign_hashed arguments");
            if args.key_id.is_empty() {
                Err(anyhow!("key id is required"))
            } else if args.msg.is_empty() {
                Err(anyhow!("base64 encoded message to sign is required"))
            } else {
                Ok(serde_json::to_value(
                    ledger::sign_transaction(args.key_id, &args.msg, ledger_conn).await?,
                )?)
            }
        }
        "keys" => {
            let mut keys = vec![];
            for i in 0..10 {
                let derivation_path = get_dervation_path(i);

                keys.push(
                    ledger::get_public_key(&derivation_path, &mut ledger_conn.0)
                        .await
                        .expect("Failed to get public key"),
                )
            }
            Ok(serde_json::to_value(KeysResponse { keys })?)
        }
        "public_key" => {
            let args = serde_json::from_value::<PublicKeyArgs>(params)
                .expect("Failed to parse sign_hashed arguments");
            Ok(serde_json::to_value(
                ledger::get_public_key(&args.key_id, &mut ledger_conn.0).await?,
            )?)
        }
        _ => Err(anyhow!("Invalid method: {}", method)),
    }
}

pub fn return_error(message: &str, id: u64) {
    println!(
        "{}",
        json!({
            "jsonrpc": "2.0",
            "error": {
                "code": 1,
                "message": message,
            },
            "id": id,
        })
    );
}

pub fn read_json_line<R: BufRead>(mut buf_reader: R) -> Result<JsonRpcRequest, serde_json::Error> {
    let mut input = String::new();
    buf_reader.read_line(&mut input).unwrap();
    serde_json::from_str(&input)
}
