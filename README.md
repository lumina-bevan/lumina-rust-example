# Miden PSWAP Example

Minimal example demonstrating PSWAP (Partial Swap) on Miden testnet.

## What This Demonstrates

A complete partial swap flow:

1. **Maker** creates PSWAP note: offers 100,000 GOLD for 100,000 SILVER
2. **Taker** fills 25%: sends 25,000 SILVER, receives 25,000 GOLD
3. **P2ID note** created with 25,000 SILVER for maker
4. **Leftover SWAPP** note created with 75,000 GOLD (still owned by maker)
5. **Maker** consumes P2ID note to receive 25,000 SILVER

### Final Verified Balances

| Account | GOLD | SILVER |
|---------|------|--------|
| Maker | 0 | 25,000 |
| Taker | 25,000 | 0 |
| Leftover Note | 75,000 | - |

## PSWAP Note Format

### NoteType (Public / Private)

In v0.13, `NoteType` is an explicit parameter when creating PSWAP notes:

- **`NoteType::Public`** — note details stored on-chain, discoverable by anyone
- **`NoteType::Private`** — only the note hash is stored on-chain

The note type is passed to both `build_swap_tag(note_type, &offered_asset, &requested_asset)` and `NoteMetadata::new(sender_id, note_type, tag)`.

### 14 Note Inputs

```
Index  Name               Description
-----  ----               -----------
 0     requested_amount   Amount of token B requested (REQUESTED_ASSET_WORD[0])
 1     zero               Always 0 (REQUESTED_ASSET_WORD[1])
 2     faucet_suffix      Token B faucet ID suffix (REQUESTED_ASSET_WORD[2])
 3     faucet_prefix      Token B faucet ID prefix (REQUESTED_ASSET_WORD[3])
 4     swapp_tag          NoteTag for SWAPP note discovery
 5     p2id_tag           NoteTag for P2ID payback notes
 6     parent_serial_0    Parent note serial number element 0 (0 for initial)
 7     parent_serial_1    Parent note serial number element 1 (0 for initial)
 8     swap_count         Times this note has been partially filled
 9     expiration_block   Block height for expiration (0 = no expiration)
10     parent_serial_2    Parent note serial number element 2 (0 for initial)
11     parent_serial_3    Parent note serial number element 3 (0 for initial)
12     creator_prefix     Creator account ID prefix
13     creator_suffix     Creator account ID suffix
```

### Note Args (for fill)

```
[0, 0, 0, fill_amount]
```

### Asset Word Format

```
[amount, 0, faucet_suffix, faucet_prefix]
```

## Account ID Prefix/Suffix

Miden account IDs are 120-bit values (30 hex characters). When split:

- **Prefix**: First 64 bits (first 16 hex chars)
- **Suffix**: Remaining 56 bits, left-shifted with trailing `00` padding

Example:
```
Account ID: 0x5451783844a1ae203e44a3b87e511e (30 hex chars)
Prefix:     0x5451783844a1ae20 (first 16 chars)
Suffix:     0x3e44a3b87e511e00 (last 14 chars + "00")
```

## Running

```bash
# Clone and enter directory
cd lumina-rust-example

# Run the simple example (no fees, ~5 minutes on testnet)
cargo run --example pswap_simple

# Run the partial fill example with fee oracle
cargo run --example pswap_partial_fill
```

## Files

- `examples/pswap_simple.rs` - Simple PSWAP example (no fees, core swap logic only)
- `examples/pswap_partial_fill.rs` - PSWAP with fee oracle integration
- `masm/notes/pswap.masm` - PSWAP note script (MASM)
- `masm/notes/pswap_with_fee.masm` - PSWAP note script with fee support

## Known Issues

### MMR Sync Panic

The Miden SDK may panic during `sync_state()` with:
```
if there is an odd element, a merge is required
```

This is a known bug where the local MMR state diverges from network state. **The transaction is still submitted successfully** - the panic happens during post-transaction sync.

The example prints midenscan links before syncing so you can verify results even if sync fails.

## Dependencies

- Miden SDK v0.13
- Tokio async runtime
- Connects to Miden testnet
