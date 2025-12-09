# Ledger Rust Signer

EXPERIMENTAL use at own risk.

## Install the Signer

Add this repo to your local `PATH`.

```bash
git clone git@github.com:MystenLabs/ledger-signer-rust.git
cd ledger-signer-rust
cargo install --path .
```

## Install the CLI Branch

Install the `external-keys-cli-support` branch of the Sui CLI to use the external keys feature.

```bash
suiup install --nightly external-keys-cli-support
```

## Add  A Key

First connect, unlock and open the sui app on your ledger device.

```bash

sui external-keys list-keys ledger-signer
# ╭────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
# │ ╭───────────┬────────────────────────────────────────────────────────────────────────────────────────────╮ │
# │ │ keyId     │  **m/44'/784'/0'/0'/0'**                                                                       │ │
# │ │ isIndexed │  false                                                                                     │ │
# │ │ key       │ ╭─────────────────┬──────────────────────────────────────────────────────────────────────╮ │ │
# │ │           │ │ alias           │                                                                      │ │ │
# │ │           │ │ suiAddress      │  **0x9776b3322d1df8ff5ff573b8f8389cea550e16a6a8e3ce6c9ed9950a81a40b0e**  │ │ │
# ...
sui external-keys add-existing "m/44'/784'/0'/0'/0'" ledger-signer
# OR
sui external-keys generate ledger-signer
```

With ledger you can use any valid derivation path with add-existing, not all paths will be present in the list-keys
output.

## Use the Key

Set your new key as active

```bash

sui client swap --address **0x9776b3322d1df8ff5ff573b8f8389cea550e16a6a8e3ce6c9ed9950a81a40b0e**
sui client transfer --object-id [object-id] --to [to address]
# confirm on your ledger
```
