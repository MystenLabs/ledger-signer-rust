use crate::constants::*;
use crate::errors::{AppError, AppResult, apdu_status_to_error};
use crate::path::build_bip32_key_payload;
use ledger_lib::{DEFAULT_TIMEOUT, Exchange, LedgerHandle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

#[allow(async_fn_in_trait)]
pub trait SuiDevice {
    async fn sui_get_public_key(
        &mut self,
        path: &str,
        display_on_device: bool,
    ) -> AppResult<Vec<u8>>;
    async fn sui_get_version(&mut self) -> AppResult<(u8, u8, u8)>;
    async fn send_chunks(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        payloads: Vec<Vec<u8>>,
    ) -> AppResult<Vec<u8>>;
    async fn handle_blocks_protocol(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        initial_payload: Vec<u8>,
        data: HashMap<String, Vec<u8>>,
    ) -> AppResult<Vec<u8>>;
    async fn exchange_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> AppResult<Vec<u8>>;
}

impl SuiDevice for LedgerHandle {
    async fn send_chunks(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        payloads: Vec<Vec<u8>>,
    ) -> AppResult<Vec<u8>> {
        let mut parameter_list = Vec::new();
        let mut data = HashMap::new();

        for payload in payloads.iter() {
            let mut chunk_list = Vec::new();
            for i in (0..payload.len()).step_by(CHUNK_SIZE) {
                let end = std::cmp::min(i + CHUNK_SIZE, payload.len());
                let chunk = payload[i..end].to_vec();
                chunk_list.push(chunk);
            }

            let mut last_hash = vec![0u8; 32];

            for chunk in chunk_list.iter().rev() {
                let mut linked_chunk = last_hash.clone();
                linked_chunk.extend_from_slice(chunk);

                let mut hasher = Sha256::new();
                hasher.update(&linked_chunk);
                last_hash = hasher.finalize().to_vec();

                let hash_hex = hex::encode(&last_hash);
                data.insert(hash_hex, linked_chunk);
            }

            parameter_list.push(last_hash.clone());
        }

        let mut initial_payload = vec![HostToLedger::Start as u8];
        for hash in parameter_list {
            initial_payload.extend_from_slice(&hash);
        }

        self.handle_blocks_protocol(cla, ins, p1, p2, initial_payload, data)
            .await
    }

    async fn handle_blocks_protocol(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        mut payload: Vec<u8>,
        mut data: HashMap<String, Vec<u8>>,
    ) -> AppResult<Vec<u8>> {
        let mut result = Vec::new();

        loop {
            let rv = self.exchange_apdu(cla, ins, p1, p2, &payload).await?;
            if rv == [0x6e, 0x00] || rv == [0x6e, 0x01] {
                return Err(AppError::WrongApp(
                    "Ledger: Sui App is not open".to_string(),
                ));
            }

            if rv == [0x55, 0x15] {
                return Err(AppError::InvalidDerivationPath(
                    "Ledger: Bad derivation path".to_string(),
                ));
            }

            if rv.len() < 3 {
                return Err(AppError::DeviceConnection(
                    "Invalid response from Ledger: too short".to_string(),
                ));
            }

            let rv_instruction = rv[0];
            let rv_payload = &rv[1..rv.len() - 2];
            let status = u16::from_be_bytes([rv[rv.len() - 2], rv[rv.len() - 1]]);

            if status != 0x9000 {
                return Err(apdu_status_to_error(status));
            }

            match rv_instruction {
                x if x == LedgerToHost::ResultAccumulating as u8 => {
                    result.extend_from_slice(rv_payload);
                    payload = vec![HostToLedger::ResultAccumulatingResponse as u8];
                }
                x if x == LedgerToHost::ResultFinal as u8 => {
                    result.extend_from_slice(rv_payload);
                    break;
                }
                x if x == LedgerToHost::GetChunk as u8 => {
                    let chunk_hash = hex::encode(rv_payload);
                    if let Some(chunk) = data.get(&chunk_hash) {
                        payload = vec![HostToLedger::GetChunkResponseSuccess as u8];
                        payload.extend_from_slice(chunk);
                    } else {
                        payload = vec![HostToLedger::GetChunkResponseFailure as u8];
                    }
                }
                x if x == LedgerToHost::PutChunk as u8 => {
                    let mut hasher = Sha256::new();
                    hasher.update(rv_payload);
                    let hash = hex::encode(hasher.finalize());
                    data.insert(hash, rv_payload.to_vec());
                    payload = vec![HostToLedger::PutChunkResponse as u8];
                }
                _ => {
                    return Err(AppError::DeviceConnection(format!(
                        "Unknown instruction from ledger: {rv_instruction}"
                    )));
                }
            }
        }

        Ok(result)
    }

    // Helper method to exchange APDU
    async fn exchange_apdu(
        &mut self,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: &[u8],
    ) -> AppResult<Vec<u8>> {
        // Build APDU: CLA INS P1 P2 LC DATA
        let mut apdu = vec![cla, ins, p1, p2];
        apdu.push(data.len() as u8);
        apdu.extend_from_slice(data);

        // Use longer timeout for signing operations that require user confirmation
        let timeout = if ins == SIGN_TRANSACTION_INS {
            std::time::Duration::from_secs(300)
        } else {
            DEFAULT_TIMEOUT
        };

        self.exchange(&apdu, timeout)
            .await
            .map_err(|e| AppError::DeviceConnection(format!("Ledger exchange error: {e}")))
    }

    async fn sui_get_version(&mut self) -> AppResult<(u8, u8, u8)> {
        let response = self
            .send_chunks(SUI_APP_CLA, GET_VERSION_INS, 0x00, 0x00, vec![vec![0u8]])
            .await?;

        if response.len() >= 3 {
            Ok((response[0], response[1], response[2]))
        } else {
            Err(AppError::DeviceInfoFailed(format!(
                "Invalid version response length: {} bytes",
                response.len()
            )))
        }
    }

    async fn sui_get_public_key(
        &mut self,
        path: &str,
        display_on_device: bool,
    ) -> AppResult<Vec<u8>> {
        let ins = if display_on_device { 0x01 } else { 0x02 };
        let path_payload = build_bip32_key_payload(path)?;

        let response = self
            .send_chunks(SUI_APP_CLA, ins, 0x00, 0x00, vec![path_payload])
            .await?;
        Ok(response)
    }
}
