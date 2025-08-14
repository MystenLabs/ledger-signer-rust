use crate::constants::*;
use crate::device::SuiDevice;
use crate::errors::AppError;
use crate::path::{build_bip32_key_payload, split_path};
use crate::types::*;
use base64::{Engine as _, engine::general_purpose};
use ledger_lib::info::Model;
use ledger_lib::transport::TcpInfo;
use ledger_lib::{Device, Filters, LedgerHandle, LedgerInfo, LedgerProvider, Transport};
use sui_sdk_types::Ed25519PublicKey;
use sui_sdk_types::hash::Hasher;
use sui_sdk_types::{Intent, IntentAppId, IntentScope, IntentVersion};

// Global state for Ledger connection
pub type LedgerConnection = (LedgerHandle, ledger_lib::LedgerInfo);

pub async fn get_connection() -> Result<(LedgerHandle, ledger_lib::LedgerInfo), AppError> {
    let mut provider = LedgerProvider::init().await;

    // Give the provider worker thread time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let devices = provider.list(Filters::Any).await?;

    if devices.is_empty() {
        return Err(AppError::DeviceNotFound);
    }

    let hardware_device_info = devices[0].clone(); // Store hardware info
    let ledger = provider.connect(devices[0].clone()).await.map_err(|e| {
        AppError::DeviceConnection(format!("Failed to connect to Ledger device: {e}"))
    })?;

    // Return the working connection with hardware info
    Ok((ledger, hardware_device_info))
}

pub async fn get_test_connection() -> Result<LedgerConnection, AppError> {
    let mut provider = LedgerProvider::init().await;

    // Give the provider worker thread time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ledger_info = LedgerInfo {
        model: Model::NanoSPlus,
        conn: TcpInfo {
            addr: "127.0.0.1:9999".parse().unwrap(),
        }
        .into(),
    };

    let ledger = provider.connect(ledger_info.clone()).await.map_err(|e| {
        AppError::DeviceConnection(format!("Failed to connect to Ledger device: {e}"))
    })?;

    // Return the working connection with hardware info
    Ok((ledger, ledger_info))
}

pub async fn get_public_key(
    derivation_path: &str,
    ledger: &mut LedgerHandle,
) -> Result<PublicKeyResponse, anyhow::Error> {
    // Get public key using Sui trait with chunking protocol (no display on device)
    let response_data = ledger.sui_get_public_key(derivation_path, false).await?;

    if response_data.is_empty() {
        return Err(
            AppError::PublicKeyFailed("Empty response from Ledger device".to_string()).into(),
        );
    }

    // Parse Sui response format: [key_size][public_key][address_size][address]
    let key_size = response_data[0] as usize;

    if response_data.len() < 1 + key_size {
        return Err(
            AppError::PublicKeyFailed("Invalid response from Ledger device".to_string()).into(),
        );
    }

    // Extract public key
    let public_key_bytes = &response_data[1..1 + key_size];

    let public_key_b64 = general_purpose::STANDARD.encode(public_key_bytes);

    // Create Ed25519PublicKey from raw bytes and derive address
    let pubkey_array: [u8; 32] = public_key_bytes
        .try_into()
        .map_err(|_| AppError::PublicKeyFailed("Invalid public key length".to_string()))?;
    let ed25519_pubkey = Ed25519PublicKey::new(pubkey_array);

    // Derive Sui address
    let sui_address = ed25519_pubkey.derive_address();

    let response = PublicKeyResponse {
        key_id: derivation_path.to_string(),
        public_key: PublicKey {
            ed25519: public_key_b64,
        },
        sui_address: sui_address.to_string(),
    };

    Ok(response)
}

pub async fn sign_transaction(
    derivation_path: String,
    transaction_bytes: &str,
    connection: LedgerConnection,
) -> Result<SignatureResponse, anyhow::Error> {
    // Parse derivation path
    let path_data = build_bip32_key_payload(&derivation_path)?;

    // Decode transaction bytes from base64
    let tx_bytes = general_purpose::STANDARD
        .decode(transaction_bytes)
        .map_err(|e| {
            AppError::InvalidTransaction(format!("Invalid base64 transaction bytes: {e}"))
        })?;

    // Prepare transaction data with intent
    let mut message_with_intent = vec![0x00, 0x00, 0x00]; // TransactionData intent
    message_with_intent.extend_from_slice(&tx_bytes);

    // First get public key for signature assembly
    let mut ledger = connection.0;

    let pub_key_response = ledger.sui_get_public_key(&derivation_path, false).await?;

    if pub_key_response.is_empty() {
        return Err(AppError::PublicKeyFailed(
            "Empty public key response from Ledger device".to_string(),
        )
        .into());
    }

    // Parse Sui response format: [key_size][public_key][address_size][address]
    let key_size = pub_key_response[0] as usize;
    if pub_key_response.len() < 1 + key_size || key_size != 32 {
        return Err(AppError::PublicKeyFailed(
            "Invalid public key response from Ledger device".to_string(),
        )
        .into());
    }

    // let public_key_bytes = &pub_key_response[1..1 + key_size];

    // Transaction payload with length prefix (like TypeScript)
    let raw_txn = message_with_intent;

    let mut hash_size = vec![0u8; 4];
    hash_size[..4].copy_from_slice(&(raw_txn.len() as u32).to_le_bytes()); // Little-endian like TypeScript
    let mut payload_txn = hash_size;
    payload_txn.extend_from_slice(&raw_txn);

    // Build payloads array: [transaction_payload, bip32_key_payload]
    let payloads = vec![payload_txn, path_data];

    let signature_data = match ledger
        .send_chunks(
            SUI_APP_CLA,
            SIGN_TRANSACTION_INS,
            0x00, // P1
            0x00, // P2
            payloads,
        )
        .await
    {
        Ok(data) => data,
        Err(e) => {
            if e.to_string().contains("timeout") || e.to_string().contains("Timeout") {
                return Err(AppError::DeviceTimeout.into());
            } else if e.to_string().contains("6985") {
                return Err(AppError::UserRejected.into());
            } else {
                return Err(
                    AppError::SignatureFailed(format!("Transaction signing failed: {e}")).into(),
                );
            }
        }
    };

    let pub_key_for_sig = ledger.sui_get_public_key(&derivation_path, false).await?;
    if pub_key_for_sig.is_empty() {
        return Err(AppError::PublicKeyFailed(
            "Empty public key response for signature assembly".to_string(),
        )
        .into());
    }

    // Parse public key from response
    let key_size = pub_key_for_sig[0] as usize;
    if pub_key_for_sig.len() < 1 + key_size || key_size != 32 {
        return Err(AppError::PublicKeyFailed(
            "Invalid public key response for signature assembly".to_string(),
        )
        .into());
    }

    let public_key_for_sig = &pub_key_for_sig[1..1 + key_size];
    let pubkey_array: [u8; 32] = public_key_for_sig
        .try_into()
        .map_err(|_| AppError::PublicKeyFailed("Invalid public key length".to_string()))?;
    let ed25519_pubkey = Ed25519PublicKey::new(pubkey_array);
    let mut sui_signature = vec![0x00]; // Ed25519 flag
    sui_signature.extend_from_slice(&signature_data); // Raw signature from Ledger
    sui_signature.extend_from_slice(ed25519_pubkey.inner()); // Public key bytes
    Ok(SignatureResponse {
        signature: general_purpose::STANDARD.encode(&sui_signature),
    })
}

pub async fn get_device_info(connection: LedgerConnection) -> Result<DeviceInfo, AppError> {
    let mut ledger = connection.0;
    let hardware_info = connection.1; // Store hardware info

    // Get general device info
    let extended_timeout = std::time::Duration::from_secs(10);
    let app_info = ledger.app_info(extended_timeout).await.map_err(|e| {
        AppError::DeviceInfoFailed(format!("Failed to get device information: {e}"))
    })?;

    let sui_version = ledger
        .sui_get_version()
        .await
        .map_err(|e| AppError::DeviceInfoFailed(format!("Failed to get Sui app version: {e}")))?;

    let sui_version_string = format!("{}.{}.{}", sui_version.0, sui_version.1, sui_version.2);

    // Extract hardware information
    let hardware_model = format!("{:?}", hardware_info.model);

    // For now, provide basic connection information
    // The ledger-lib API doesn't expose detailed connection info through pattern matching
    let connection_type = "Connected".to_string();
    let usb_vendor_id: Option<u16> = None;
    let usb_product_id: Option<u16> = None;
    let usb_path: Option<String> = None;

    let device_info_response = DeviceInfo {
        device_name: app_info.name,
        device_version: app_info.version,
        sui_app_version: sui_version_string,
        sui_app_major: sui_version.0,
        sui_app_minor: sui_version.1,
        sui_app_patch: sui_version.2,
        hardware_model,
        connection_type,
        usb_vendor_id,
        usb_product_id,
        usb_path,
    };

    Ok(device_info_response)
}

// Cross-validation commands for supply chain attack prevention

pub async fn cross_validate_public_key_derivation(
    public_key_base64: String,
    derivation_path: String,
) -> Result<CrossValidationPublicKeyResponse, AppError> {
    // Decode public key from base64
    let public_key_bytes = general_purpose::STANDARD
        .decode(&public_key_base64)
        .map_err(|e| {
            //error!("❌ Failed to decode base64 public key: {}", e);
            AppError::InvalidTransaction(format!("Invalid base64 public key: {e}"))
        })?;

    if public_key_bytes.len() != 32 {
        return Err(AppError::PublicKeyFailed(format!(
            "Invalid public key length: {} bytes, expected 32",
            public_key_bytes.len()
        )));
    }

    // Create Ed25519PublicKey and derive address
    let pubkey_array: [u8; 32] = public_key_bytes
        .clone()
        .try_into()
        .map_err(|_| AppError::PublicKeyFailed("Invalid public key length".to_string()))?;
    let ed25519_pubkey = Ed25519PublicKey::new(pubkey_array);
    let sui_address = ed25519_pubkey.derive_address();

    // Parse derivation path
    let derivation_components = split_path(&derivation_path)?;

    let public_key_hex = hex::encode(&public_key_bytes);

    let response = CrossValidationPublicKeyResponse {
        public_key_base64,
        public_key_hex,
        public_key_bytes,
        sui_address: sui_address.to_string(),
        derivation_path,
        derivation_components,
    };

    Ok(response)
}

pub async fn cross_validate_ledger_hash(
    transaction_bytes_base64: String,
) -> Result<CrossValidationLedgerHashResponse, AppError> {
    // Decode transaction bytes from base64
    let transaction_bytes = general_purpose::STANDARD
        .decode(&transaction_bytes_base64)
        .map_err(|e| {
            AppError::InvalidTransaction(format!("Invalid base64 transaction bytes: {e}"))
        })?;

    // Compute Ledger Hash (intent + transaction data) - following signing_digest pattern
    let intent = Intent::new(
        IntentScope::TransactionData,
        IntentVersion::V0,
        IntentAppId::Sui,
    );

    let mut ledger_hasher = Hasher::new();
    ledger_hasher.update(intent.to_bytes());
    ledger_hasher.update(&transaction_bytes);

    let ledger_digest = ledger_hasher.finalize();
    let ledger_hash = ledger_digest.into_inner().to_vec();

    // Debug logging for cross-validation
    let intent_prefix = intent.to_bytes();

    // For response, we need to construct the intent message manually for comparison
    let mut intent_message_bytes =
        Vec::with_capacity(intent_prefix.len() + transaction_bytes.len());
    intent_message_bytes.extend_from_slice(&intent_prefix);
    intent_message_bytes.extend_from_slice(&transaction_bytes);

    let response = CrossValidationLedgerHashResponse {
        transaction_bytes_base64,
        transaction_bytes_hex: hex::encode(&transaction_bytes),
        transaction_bytes,
        intent_message: intent_message_bytes.clone(),
        intent_message_hex: hex::encode(&intent_message_bytes),
        ledger_hash: ledger_hash.clone(),
        ledger_hash_hex: format!("0x{}", hex::encode(&ledger_hash)),
    };

    //info!("✅ Cross-validation ledger hash completed");
    //debug!("📊 Rust computed ledger hash: {}", response.ledger_hash_hex);
    //debug!("📊 Intent message: {} bytes", response.intent_message.len());

    Ok(response)
}

pub async fn cross_validate_signature_format(
    signature_base64: String,
) -> Result<CrossValidationSignatureResponse, AppError> {
    //info!("🔍 Cross-validating signature format");
    //info!("📝 Signature length: {} chars", signature_base64.len());

    // Decode signature from base64
    let signature_bytes = general_purpose::STANDARD
        .decode(&signature_base64)
        .map_err(|e| {
            //error!("❌ Failed to decode base64 signature: {}", e);
            AppError::InvalidTransaction(format!("Invalid base64 signature: {e}"))
        })?;

    let is_valid_length = signature_bytes.len() == 97;

    if !is_valid_length {
        //warn!(
        //     "⚠️ Invalid signature length: {} bytes, expected 97",
        //     signature_bytes.len()
        // );
        return Ok(CrossValidationSignatureResponse {
            signature_base64,
            signature_bytes: signature_bytes.clone(),
            signature_hex: hex::encode(&signature_bytes),
            scheme: 255, // Invalid scheme
            raw_signature: vec![],
            public_key: vec![],
            public_key_hex: String::new(),
            is_valid_length,
            is_ed25519: false,
        });
    }

    // Parse signature components
    let scheme = signature_bytes[0];
    let raw_signature = signature_bytes[1..65].to_vec();
    let public_key = signature_bytes[65..97].to_vec();
    let is_ed25519 = scheme == 0;

    let response = CrossValidationSignatureResponse {
        signature_base64,
        signature_bytes: signature_bytes.clone(),
        signature_hex: hex::encode(&signature_bytes),
        scheme,
        raw_signature,
        public_key: public_key.clone(),
        public_key_hex: hex::encode(&public_key),
        is_valid_length,
        is_ed25519,
    };

    Ok(response)
}

pub async fn cross_validate_derivation_path(
    derivation_path: String,
) -> Result<CrossValidationDerivationPathResponse, AppError> {
    // Normalize Unicode quotes to ASCII
    let normalized_path = derivation_path
        .replace("\\'", "'")
        .replace("\u{2019}", "'") // U+2019 RIGHT SINGLE QUOTATION MARK
        .replace("\u{2018}", "'") // U+2018 LEFT SINGLE QUOTATION MARK
        .replace("\u{2032}", "'") // U+2032 PRIME
        .replace("\u{201B}", "'") // U+201B SINGLE HIGH-REVERSED-9 QUOTATION MARK
        .replace("\u{201C}", "'") // U+201C LEFT DOUBLE QUOTATION MARK
        .replace("\u{201D}", "'") // U+201D RIGHT DOUBLE QUOTATION MARK
        .replace("\"", "'") // Regular ASCII double quote
        .replace("''", "'"); // Multiple apostrophes

    let mut error_msg: Option<String> = None;
    let mut components = Vec::new();
    let mut is_valid = true;

    // Parse derivation path
    match split_path(&normalized_path) {
        Ok(parsed_components) => {
            components = parsed_components;
        }
        Err(e) => {
            error_msg = Some(e.to_string());
            is_valid = false;
        }
    }

    // Build BIP32 payload
    let mut bip32_payload = Vec::new();
    if is_valid {
        match build_bip32_key_payload(&normalized_path) {
            Ok(payload) => {
                bip32_payload = payload;
            }
            Err(e) => {
                error_msg = Some(e.to_string());
                is_valid = false;
            }
        }
    }

    let components_hex: Vec<String> = components.iter().map(|c| format!("0x{c:08x}")).collect();

    let response = CrossValidationDerivationPathResponse {
        original_path: derivation_path,
        normalized_path,
        is_valid,
        components,
        components_hex,
        bip32_payload: bip32_payload.clone(),
        bip32_payload_hex: hex::encode(&bip32_payload),
        error: error_msg,
    };

    Ok(response)
}

pub async fn analyze_transaction_bytes(
    transaction_bytes_base64: String,
) -> Result<TransactionAnalysisResponse, AppError> {
    use bcs;
    use sui_sdk_types::{Command, Input, Transaction, TransactionKind};

    // Decode transaction bytes from base64
    let transaction_bytes = general_purpose::STANDARD
        .decode(&transaction_bytes_base64)
        .map_err(|e| {
            AppError::InvalidTransaction(format!("Invalid base64 transaction bytes: {e}"))
        })?;

    // Deserialize transaction using BCS
    let transaction: Transaction = bcs::from_bytes(&transaction_bytes)
        .map_err(|e| AppError::InvalidTransaction(format!("Failed to parse transaction: {e}")))?;

    // Extract transaction details
    let sender = transaction.sender.to_string();
    let gas_budget = transaction.gas_payment.budget;
    let gas_price = transaction.gas_payment.price;
    let gas_owner = transaction.gas_payment.owner.to_string();

    // Extract gas objects
    let gas_objects: Vec<GasObjectInfo> = transaction
        .gas_payment
        .objects
        .iter()
        .map(|obj_ref| GasObjectInfo {
            object_id: obj_ref.object_id().to_string(),
            version: obj_ref.version(),
            digest: obj_ref.digest().to_string(),
        })
        .collect();

    // Analyze transaction kind
    let (transaction_type, commands, inputs) = match &transaction.kind {
        TransactionKind::ProgrammableTransaction(pt) => {
            let commands_info: Vec<CommandInfo> = pt
                .commands
                .iter()
                .enumerate()
                .map(|(idx, cmd)| {
                    let (command_type, details) = match cmd {
                        Command::MoveCall(move_call) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "package".to_string(),
                                serde_json::Value::String(move_call.package.to_string()),
                            );
                            details.insert(
                                "module".to_string(),
                                serde_json::Value::String(move_call.module.to_string()),
                            );
                            details.insert(
                                "function".to_string(),
                                serde_json::Value::String(move_call.function.to_string()),
                            );
                            details.insert(
                                "type_arguments".to_string(),
                                serde_json::Value::Array(
                                    move_call
                                        .type_arguments
                                        .iter()
                                        .map(|t| serde_json::Value::String(format!("{t}")))
                                        .collect(),
                                ),
                            );
                            details.insert(
                                "arguments".to_string(),
                                serde_json::Value::Array(
                                    move_call
                                        .arguments
                                        .iter()
                                        .map(|arg| serde_json::Value::String(format_argument(arg)))
                                        .collect(),
                                ),
                            );
                            ("MoveCall".to_string(), serde_json::Value::Object(details))
                        }
                        Command::TransferObjects(transfer) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "objects".to_string(),
                                serde_json::Value::Array(
                                    transfer
                                        .objects
                                        .iter()
                                        .map(|arg| serde_json::Value::String(format_argument(arg)))
                                        .collect(),
                                ),
                            );
                            details.insert(
                                "address".to_string(),
                                serde_json::Value::String(format_argument(&transfer.address)),
                            );
                            (
                                "TransferObjects".to_string(),
                                serde_json::Value::Object(details),
                            )
                        }
                        Command::SplitCoins(split) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "coin".to_string(),
                                serde_json::Value::String(format_argument(&split.coin)),
                            );
                            details.insert(
                                "amounts".to_string(),
                                serde_json::Value::Array(
                                    split
                                        .amounts
                                        .iter()
                                        .map(|arg| serde_json::Value::String(format_argument(arg)))
                                        .collect(),
                                ),
                            );
                            ("SplitCoins".to_string(), serde_json::Value::Object(details))
                        }
                        Command::MergeCoins(merge) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "coin".to_string(),
                                serde_json::Value::String(format_argument(&merge.coin)),
                            );
                            details.insert(
                                "coins_to_merge".to_string(),
                                serde_json::Value::Array(
                                    merge
                                        .coins_to_merge
                                        .iter()
                                        .map(|arg| serde_json::Value::String(format_argument(arg)))
                                        .collect(),
                                ),
                            );
                            ("MergeCoins".to_string(), serde_json::Value::Object(details))
                        }
                        Command::Publish(publish) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "modules_count".to_string(),
                                serde_json::Value::Number(publish.modules.len().into()),
                            );
                            details.insert(
                                "dependencies".to_string(),
                                serde_json::Value::Array(
                                    publish
                                        .dependencies
                                        .iter()
                                        .map(|id| serde_json::Value::String(id.to_string()))
                                        .collect(),
                                ),
                            );
                            ("Publish".to_string(), serde_json::Value::Object(details))
                        }
                        Command::Upgrade(upgrade) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "package".to_string(),
                                serde_json::Value::String(upgrade.package.to_string()),
                            );
                            details.insert(
                                "ticket".to_string(),
                                serde_json::Value::String(format_argument(&upgrade.ticket)),
                            );
                            details.insert(
                                "modules_count".to_string(),
                                serde_json::Value::Number(upgrade.modules.len().into()),
                            );
                            details.insert(
                                "dependencies".to_string(),
                                serde_json::Value::Array(
                                    upgrade
                                        .dependencies
                                        .iter()
                                        .map(|id| serde_json::Value::String(id.to_string()))
                                        .collect(),
                                ),
                            );
                            ("Upgrade".to_string(), serde_json::Value::Object(details))
                        }
                        Command::MakeMoveVector(make_vec) => {
                            let mut details = serde_json::Map::new();
                            if let Some(type_tag) = &make_vec.type_ {
                                details.insert(
                                    "type".to_string(),
                                    serde_json::Value::String(format!("{type_tag}")),
                                );
                            }
                            details.insert(
                                "elements".to_string(),
                                serde_json::Value::Array(
                                    make_vec
                                        .elements
                                        .iter()
                                        .map(|arg| serde_json::Value::String(format_argument(arg)))
                                        .collect(),
                                ),
                            );
                            (
                                "MakeMoveVector".to_string(),
                                serde_json::Value::Object(details),
                            )
                        }
                    };

                    CommandInfo {
                        index: idx,
                        command_type,
                        details,
                    }
                })
                .collect();

            let inputs_info: Vec<InputInfo> = pt
                .inputs
                .iter()
                .enumerate()
                .map(|(idx, input)| {
                    let (input_type, details) = match input {
                        Input::Pure { value } => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "value_hex".to_string(),
                                serde_json::Value::String(hex::encode(value)),
                            );
                            details.insert(
                                "value_base64".to_string(),
                                serde_json::Value::String(general_purpose::STANDARD.encode(value)),
                            );
                            details.insert(
                                "size_bytes".to_string(),
                                serde_json::Value::Number(value.len().into()),
                            );

                            // Try to decode as common types
                            if let Ok(decoded_str) = String::from_utf8(value.clone()) {
                                details.insert(
                                    "decoded_as_string".to_string(),
                                    serde_json::Value::String(decoded_str),
                                );
                            }
                            if value.len() == 8
                                && let Ok(bytes) = <[u8; 8]>::try_from(value.as_slice())
                            {
                                let as_u64 = u64::from_le_bytes(bytes);
                                details.insert(
                                    "decoded_as_u64".to_string(),
                                    serde_json::Value::Number(as_u64.into()),
                                );
                            }

                            ("Pure".to_string(), serde_json::Value::Object(details))
                        }
                        Input::ImmutableOrOwned(obj_ref) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "object_id".to_string(),
                                serde_json::Value::String(obj_ref.object_id().to_string()),
                            );
                            details.insert(
                                "version".to_string(),
                                serde_json::Value::Number(obj_ref.version().into()),
                            );
                            details.insert(
                                "digest".to_string(),
                                serde_json::Value::String(obj_ref.digest().to_string()),
                            );
                            (
                                "ImmutableOrOwned".to_string(),
                                serde_json::Value::Object(details),
                            )
                        }
                        Input::Shared {
                            object_id,
                            initial_shared_version,
                            mutable,
                        } => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "object_id".to_string(),
                                serde_json::Value::String(object_id.to_string()),
                            );
                            details.insert(
                                "initial_shared_version".to_string(),
                                serde_json::Value::Number((*initial_shared_version).into()),
                            );
                            details
                                .insert("mutable".to_string(), serde_json::Value::Bool(*mutable));
                            ("Shared".to_string(), serde_json::Value::Object(details))
                        }
                        Input::Receiving(obj_ref) => {
                            let mut details = serde_json::Map::new();
                            details.insert(
                                "object_id".to_string(),
                                serde_json::Value::String(obj_ref.object_id().to_string()),
                            );
                            details.insert(
                                "version".to_string(),
                                serde_json::Value::Number(obj_ref.version().into()),
                            );
                            details.insert(
                                "digest".to_string(),
                                serde_json::Value::String(obj_ref.digest().to_string()),
                            );
                            ("Receiving".to_string(), serde_json::Value::Object(details))
                        }
                    };

                    InputInfo {
                        index: idx,
                        input_type,
                        details,
                    }
                })
                .collect();

            (
                "ProgrammableTransaction".to_string(),
                commands_info,
                inputs_info,
            )
        }
        _ => {
            // Handle other transaction kinds if needed
            ("Other".to_string(), vec![], vec![])
        }
    };

    // Calculate transaction digest
    let tx_digest = transaction.digest();

    // Compute intent message and ledger hash
    let intent = Intent::new(
        IntentScope::TransactionData,
        IntentVersion::V0,
        IntentAppId::Sui,
    );

    let mut ledger_hasher = Hasher::new();
    ledger_hasher.update(intent.to_bytes());
    ledger_hasher.update(&transaction_bytes);
    let ledger_hash = ledger_hasher.finalize();

    let response = TransactionAnalysisResponse {
        transaction_digest: tx_digest.to_string(),
        sender,
        gas_budget,
        gas_price,
        gas_owner,
        gas_objects,
        transaction_type,
        commands,
        inputs,
        expiration: match transaction.expiration {
            sui_sdk_types::TransactionExpiration::None => None,
            sui_sdk_types::TransactionExpiration::Epoch(e) => Some(format!("Epoch {e}")),
        },
        raw_size_bytes: transaction_bytes.len(),
        ledger_hash_hex: format!("0x{}", hex::encode(ledger_hash.into_inner())),
    };

    //info!("✅ Transaction analysis completed");
    Ok(response)
}

fn format_argument(arg: &sui_sdk_types::Argument) -> String {
    use sui_sdk_types::Argument;
    match arg {
        Argument::Gas => "Gas".to_string(),
        Argument::Input(idx) => format!("Input({idx})"),
        Argument::Result(idx) => format!("Result({idx})"),
        Argument::NestedResult(idx, nested_idx) => format!("NestedResult({idx}, {nested_idx})"),
    }
}
