pub const EMULATOR_HOST: &str = "127.0.0.1";
pub const EMULATOR_PORT: u16 = 5001;
pub const EMULATOR_BUTTON_BASE_URL: &str = "http://127.0.0.1:5001/button";
pub const EMULATOR_EVENTS_URL: &str = "http://127.0.0.1:5001/events";
pub const EMULATOR_MAX_ATTEMPTS: u32 = 10;

// Home
pub const EMULATOR_SUI_TEXT: &str = "Sui";
pub const EMULATOR_SETTINGS_TEXT: &str = "Settings";
pub const EMULATOR_QUIT_TEXT: &str = "Quit";
pub const EMULATOR_HOME: &[&str] = &[EMULATOR_SUI_TEXT, EMULATOR_SETTINGS_TEXT, EMULATOR_QUIT_TEXT];

// Settings
pub const EMULATOR_ENABLED_TEXT: &str = "Enabled";
pub const EMULATOR_DISABLED_TEXT: &str = "Disabled";
pub const EMULATOR_BACK_TEXT: &str = "Back";
pub const EMULATOR_SETTINGS: &[&str] = &[EMULATOR_ENABLED_TEXT, EMULATOR_DISABLED_TEXT, EMULATOR_BACK_TEXT];

// Signing
pub const EMULATOR_ACCEPT_TEXT: &str = "Accept and send";
pub const EMULATOR_NOT_RECOGNIZED_TEXT: &str = "not recognized";
pub const EMULATOR_REJECT_TEXT: &str = "Reject";
pub const EMULATOR_SIGN: &[&str] = &[EMULATOR_ACCEPT_TEXT, EMULATOR_NOT_RECOGNIZED_TEXT, EMULATOR_REJECT_TEXT];
