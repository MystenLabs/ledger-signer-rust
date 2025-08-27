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
