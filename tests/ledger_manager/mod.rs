#![allow(dead_code)]

use anyhow::Result;
use lazy_static::lazy_static;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fmt::Display;

use crate::ledger_manager::constants::*;

pub mod constants;

lazy_static! {
    static ref LEDGER_MANAGER: tokio::sync::Mutex<LedgerManager> =
        tokio::sync::Mutex::new(LedgerManager::new());
}

pub struct LedgerManager {
    client: Client,
    blind_signing: bool,
}

impl LedgerManager {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
            blind_signing: false,
        }
    }

    pub async fn acquire() -> tokio::sync::MutexGuard<'static, Self> {
        LEDGER_MANAGER.lock().await
    }

    /// Base state, should be able to go to home from any state
    pub async fn go_home(&self) -> Result<()> {
        let mut i = 0;
        while i < 5 {
            i += 1;
            match self.location().await? {
                Location::Home => return Ok(()),
                Location::Settings => {
                    self.send_until_event(SendKey::Right, &[EMULATOR_BACK_TEXT])
                        .await?;
                    self.send_keys(SendKey::Both).await?;
                }
                Location::Signing => {
                    self.send_until_event(SendKey::Right, &[EMULATOR_REJECT_TEXT])
                        .await?;
                    self.send_keys(SendKey::Both).await?;
                }
                Location::Unknown => {
                    // In some cases we can find our way out by pressing right
                    self.send_keys(SendKey::Right).await?;
                }
            }
        }
        Err(anyhow::anyhow!("Failed to go home"))
    }

    pub async fn in_home(&self) -> Result<()> {
        if self.assert_last_event_one_of(EMULATOR_HOME).await.is_err() {
            self.send_keys(SendKey::Right).await?; // Might be version, try again
        }
        self.assert_last_event_one_of(EMULATOR_HOME).await?;
        Ok(())
    }

    /// Need to be in home to go to settings
    pub async fn go_settings(&self) -> Result<()> {
        self.send_until_event(SendKey::Right, &[EMULATOR_SETTINGS_TEXT])
            .await?;
        self.send_keys(SendKey::Both).await?;
        self.in_settings().await?;
        Ok(())
    }

    pub async fn in_settings(&self) -> Result<()> {
        self.assert_last_event_one_of(EMULATOR_SETTINGS).await?;
        Ok(())
    }

    pub async fn location(&self) -> Result<Location> {
        let last_event = self.last_event().await?;
        if EMULATOR_SETTINGS.contains(&last_event.text.as_str()) {
            Ok(Location::Settings)
        } else if EMULATOR_HOME.contains(&last_event.text.as_str()) {
            Ok(Location::Home)
        } else if EMULATOR_SIGN.contains(&last_event.text.as_str()) {
            Ok(Location::Signing)
        } else {
            Ok(Location::Unknown)
        }
    }

    /// Need to be in signing to accept transaction
    pub async fn accept_transaction(&self) -> Result<()> {
        self.assert_last_event_one_of(EMULATOR_SIGN).await?;
        self.send_until_event(SendKey::Right, &[EMULATOR_ACCEPT_TEXT])
            .await?;
        self.send_keys(SendKey::Both).await?;
        Ok(())
    }

    pub async fn enable_blind_signing(&mut self) -> Result<()> {
        if self.blind_signing {
            return Ok(());
        }

        self.go_home().await?;
        self.go_settings().await?;

        if self.assert_last_event("Enabled").await.is_ok() {
            self.blind_signing = true;
        } else {
            self.send_keys(SendKey::Both).await?;
            self.assert_last_event("Enabled").await?;
        }

        self.blind_signing = true;
        Ok(())
    }

    pub async fn send_until_event(&self, key: SendKey, expected_text: &[&str]) -> Result<()> {
        let mut attempts: u32 = 0;
        while attempts < EMULATOR_MAX_ATTEMPTS {
            if self.assert_last_event_one_of(expected_text).await.is_ok() {
                return Ok(());
            }
            self.send_keys(key).await?;
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            attempts += 1;
        }
        Err(anyhow::anyhow!("Failed to find event: {expected_text:?}"))
    }

    pub async fn accept_and_send(&self) -> Result<()> {
        self.send_until_event(SendKey::Right, EMULATOR_SIGN).await?;
        Ok(())
    }

    pub async fn send_keys(&self, key: SendKey) -> Result<()> {
        let url = format!("{}/{}", EMULATOR_BUTTON_BASE_URL, key);
        let response = self
            .client
            .post(url)
            .json(&serde_json::json!({"action": "press-and-release"}))
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send button press: {e}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to send button press"))
        }
    }

    pub async fn last_event(&self) -> Result<Event> {
        let response = self
            .client
            .get(EMULATOR_EVENTS_URL)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to get last event: {e}"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Failed to get last event"));
        }

        let events: EventsResponse = response
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to parse events: {e}"))?;

        if let Some(last_event) = events.events.last() {
            Ok(last_event.clone())
        } else {
            Err(anyhow::anyhow!("No events found"))
        }
    }

    pub async fn assert_last_event(&self, expected_text: &str) -> Result<()> {
        let actual_text = self.last_event().await?.text;
        if actual_text == expected_text {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Unexpected event: {actual_text} expected: {expected_text}"
            ))
        }
    }

    pub async fn assert_last_event_one_of(&self, expected_texts: &[&str]) -> Result<()> {
        let actual_text = self.last_event().await?.text;
        if expected_texts.contains(&actual_text.as_str()) {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Unexpected event: \"{actual_text}\" expected one of: {expected_texts:?}"
            ))
        }
    }
}

pub enum Location {
    Home,
    Settings,
    Signing,
    Unknown,
}

#[derive(Clone, Copy)]
pub enum SendKey {
    Left,
    Right,
    Both,
}

impl Display for SendKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendKey::Left => write!(f, "left"),
            SendKey::Right => write!(f, "right"),
            SendKey::Both => write!(f, "both"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Event {
    pub text: String,
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
    pub clear: bool,
}

impl Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Event(text: {}, x: {}, y: {}, w: {}, h: {}, clear: {})",
            self.text, self.x, self.y, self.w, self.h, self.clear
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EventsResponse {
    events: Vec<Event>,
}
