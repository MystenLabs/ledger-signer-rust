//! API response types for Ledger Signer
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub params: serde_json::Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Value,
    pub id: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignParams {
    pub key_id: String,
    pub msg: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKeyParams {
    pub key_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeysResponse {
    pub keys: Vec<PublicKeyResponse>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicKey {
    #[serde(rename = "Ed25519")]
    pub ed25519: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PublicKeyResponse {
    pub key_id: String,
    pub public_key: PublicKey,
    pub sui_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignatureResponse {
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_name: String,
    pub device_version: String,
    pub sui_app_version: String,
    pub sui_app_major: u8,
    pub sui_app_minor: u8,
    pub sui_app_patch: u8,
    pub hardware_model: String,
    pub connection_type: String,
    pub usb_vendor_id: Option<u16>,
    pub usb_product_id: Option<u16>,
    pub usb_path: Option<String>,
}

// Cross-validation response types for supply chain attack prevention#[derive(Debug, Serialize, Deserialize)]
pub struct CrossValidationPublicKeyResponse {
    pub public_key_base64: String,
    pub public_key_hex: String,
    pub public_key_bytes: Vec<u8>,
    pub sui_address: String,
    pub derivation_path: String,
    pub derivation_components: Vec<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossValidationLedgerHashResponse {
    pub transaction_bytes_base64: String,
    pub transaction_bytes_hex: String,
    pub transaction_bytes: Vec<u8>,
    pub intent_message: Vec<u8>,
    pub intent_message_hex: String,
    // Ledger Hash (intent + transaction data)
    pub ledger_hash: Vec<u8>,
    pub ledger_hash_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossValidationSignatureResponse {
    pub signature_base64: String,
    pub signature_bytes: Vec<u8>,
    pub signature_hex: String,
    pub scheme: u8,
    pub raw_signature: Vec<u8>,
    pub public_key: Vec<u8>,
    pub public_key_hex: String,
    pub is_valid_length: bool,
    pub is_ed25519: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CrossValidationDerivationPathResponse {
    pub original_path: String,
    pub normalized_path: String,
    pub is_valid: bool,
    pub components: Vec<u32>,
    pub components_hex: Vec<String>,
    pub bip32_payload: Vec<u8>,
    pub bip32_payload_hex: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TransactionAnalysisResponse {
    pub transaction_digest: String,
    pub sender: String,
    pub gas_budget: u64,
    pub gas_price: u64,
    pub gas_owner: String,
    pub gas_objects: Vec<GasObjectInfo>,
    pub transaction_type: String,
    pub commands: Vec<CommandInfo>,
    pub inputs: Vec<InputInfo>,
    pub expiration: Option<String>,
    pub raw_size_bytes: usize,
    pub ledger_hash_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GasObjectInfo {
    pub object_id: String,
    pub version: u64,
    pub digest: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandInfo {
    pub index: usize,
    pub command_type: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InputInfo {
    pub index: usize,
    pub input_type: String,
    pub details: serde_json::Value,
}
