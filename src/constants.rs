//! Constants and protocol definitions for Sui Ledger App communication

// Sui Ledger App constants (matching TypeScript implementation)
pub const SUI_APP_CLA: u8 = 0x00;
pub const GET_VERSION_INS: u8 = 0x00;
// Note: Public key instruction is set inline: 0x01 for display, 0x02 for no display
pub const SIGN_TRANSACTION_INS: u8 = 0x03;
pub const CHUNK_SIZE: usize = 180;

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
