//! BIP32 derivation path parsing utilities
use crate::errors::{AppError, AppResult};

/// Build BIP32 key payload from derivation path
pub fn build_bip32_key_payload(path: &str) -> AppResult<Vec<u8>> {
    let paths = split_path(path)?;

    // BIP32 payload: [num_components][component1][component2]...[componentN]
    let mut payload = vec![paths.len() as u8];
    for element in paths {
        payload.extend_from_slice(&element.to_le_bytes()); // Little-endian
    }

    Ok(payload)
}

/// Simple and robust derivation path parser
pub fn split_path(path: &str) -> AppResult<Vec<u32>> {
    let mut result = Vec::new();

    for (i, component) in path.split('/').enumerate() {
        if i == 0 {
            if component != "m" {
                return Err(AppError::InvalidDerivationPath(format!(
                    "Derivation path must start with 'm', found '{}'",
                    component
                )));
            }
            continue;
        }

        if component.is_empty() {
            continue;
        }

        // Strip all trailing quote characters using a simpler approach
        let mut working_component = component.to_string();
        let mut is_hardened = false;

        // Define all quote characters we want to strip
        let quote_chars = [
            '\'', '\u{2019}', '\u{2018}', '\u{2032}', '\u{201B}', '"', '\u{201C}', '\u{201D}',
        ];

        // Keep removing quote characters from the end
        loop {
            let original_len = working_component.len();
            let mut found_quote = false;

            // Check for any quote character at the end
            if let Some(last_char) = working_component.chars().last()
                && quote_chars.contains(&last_char)
            {
                // Remove the last character
                working_component.pop();
                is_hardened = true;
                found_quote = true;
            }

            if !found_quote || working_component.len() >= original_len {
                break;
            }
        }

        let num_str = &working_component;

        // Parse the number
        let mut number = num_str.parse::<u32>().map_err(|_| {
            AppError::InvalidDerivationPath(format!(
                "Invalid path component: '{component}' (could not parse numeric part '{num_str}')",
            ))
        })?;

        // Apply hardened flag
        if is_hardened {
            number += 0x80000000;
        }

        result.push(number);
    }

    Ok(result)
}

pub fn get_dervation_path(index: u32) -> String {
    // 44'/784'/0'/0'/0'
    format!("m/44'/784'/0'/0'/{index}'")
}
