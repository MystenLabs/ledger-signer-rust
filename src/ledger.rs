use crate::constants::*;
use crate::device::SuiDevice;
use crate::errors::AppError;
use crate::path::build_bip32_key_payload;
use crate::types::*;
use base64::{Engine as _, engine::general_purpose};
use ledger_lib::info::Model;
use ledger_lib::transport::TcpInfo;
use ledger_lib::{Device, Filters, LedgerHandle, LedgerInfo, LedgerProvider, Transport};
use sui_sdk_types::Ed25519PublicKey;

// Global state for Ledger connection
pub type LedgerConnection = (LedgerHandle, ledger_lib::LedgerInfo);

pub enum ConnectionType {
    Auto,
    Tcp(u16),
}

pub async fn get_connection(
    connection_type: ConnectionType,
) -> Result<(LedgerHandle, ledger_lib::LedgerInfo), AppError> {
    if let ConnectionType::Tcp(port) = connection_type {
        return get_tcp_connection(port).await.map_err(|_| {
            AppError::DeviceConnection("Failed to connect to Ledger device over TCP".to_string())
        });
    }

    let mut provider = LedgerProvider::init().await;

    // Give the provider worker thread time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let devices = provider.list(Filters::Any).await?;

    if devices.is_empty() {
        return Err(AppError::DeviceNotFound.into());
    }

    let hardware_device_info = devices[0].clone(); // Store hardware info
    let ledger = provider.connect(devices[0].clone()).await.map_err(|e| {
        AppError::DeviceConnection(format!("Failed to connect to Ledger device: {e}"))
    })?;

    // Return the working connection with hardware info
    Ok((ledger, hardware_device_info))
}

pub async fn get_tcp_connection(port: u16) -> Result<LedgerConnection, anyhow::Error> {
    let mut provider = LedgerProvider::init().await;

    // Give the provider worker thread time to initialize
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let ledger_info = LedgerInfo {
        model: Model::NanoSPlus,
        conn: TcpInfo {
            addr: format!("127.0.0.1:{}", port).parse().unwrap(),
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
) -> Result<PublicKeyResponse, AppError> {
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
    connection: &mut LedgerConnection,
) -> Result<SignatureResponse, AppError> {
    let ledger = &mut connection.0;
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

pub async fn get_device_info(connection: &mut LedgerConnection) -> Result<DeviceInfo, AppError> {
    let ledger = &mut connection.0;
    let hardware_info = &mut connection.1;

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
