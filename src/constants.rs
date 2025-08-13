//! Constants and protocol definitions for Sui Ledger App communication

// Sui Ledger App constants (matching TypeScript implementation)
pub const SUI_APP_CLA: u8 = 0x00;
pub const GET_VERSION_INS: u8 = 0x00;
// Note: Public key instruction is set inline: 0x01 for display, 0x02 for no display
pub const SIGN_TRANSACTION_INS: u8 = 0x03;
pub const CHUNK_SIZE: usize = 180;

// Emulator/test constants
pub const EMULATOR_HOST: &str = "127.0.0.1";
pub const EMULATOR_PORT: u16 = 5001;
pub const EMULATOR_BUTTON_BASE_URL: &str = "http://127.0.0.1:5001/button";
pub const EMULATOR_EVENTS_URL: &str = "http://127.0.0.1:5001/events";
pub const EMULATOR_MAX_ATTEMPTS: u32 = 10;

// Sui chunking protocol enums (from TypeScript SDK)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LedgerToHost {
    ResultAccumulating = 0,
    ResultFinal = 1,
    GetChunk = 2,
    PutChunk = 3,
}

#[derive(Debug, Clone, Copy)]
pub enum HostToLedger {
    Start = 0,
    GetChunkResponseSuccess = 1,
    GetChunkResponseFailure = 2,
    PutChunkResponse = 3,
    ResultAccumulatingResponse = 4,
}
