# Miden PSWAP Example

Minimal example demonstrating PSWAP (Partial Swap) on Miden testnet.

## What This Demonstrates

A complete partial swap flow:

1. **Maker** creates PSWAP note: offers 1000 GOLD for 1000 SILVER
2. **Taker** fills 25%: sends 250 SILVER, receives 250 GOLD
3. **P2ID note** created with 250 SILVER for maker
4. **Leftover SWAPP** note created with 750 GOLD (still owned by maker)
5. **Maker** consumes P2ID note to receive 250 SILVER

### Final Verified Balances

| Account | GOLD | SILVER |
|---------|------|--------|
| Maker | 0 | 250 |
| Taker | 250 | 0 |
| Leftover Note | 750 | - |

## PSWAP Note Format

### 14 Note Inputs (CLOB Format)

```
Index  Name               Description
-----  ----               -----------
 0     requested_amount   Amount of token B requested
 1     zero               Always 0
 2     faucet_suffix      Token B faucet ID suffix (with trailing 00 padding)
 3     faucet_prefix      Token B faucet ID prefix
 4     swapp_tag          NoteTag for SWAPP note discovery
 5     p2id_tag           NoteTag for P2ID payback notes
 6-7   empty              Reserved (0)
 8     swap_count         Times this note has been partially filled
 9     expiration_block   Block height for expiration (0 = no expiration)
10-11  empty              Reserved (0)
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

# Run the example (takes ~5 minutes on testnet)
cargo run --example pswap_partial_fill
```

## Files

- `examples/pswap_partial_fill.rs` - Main example code
- `masm/notes/pswap.masm` - PSWAP note script (MASM)

## Known Issues

### MMR Sync Panic

The Miden SDK may panic during `sync_state()` with:
```
if there is an odd element, a merge is required
```

This is a known bug where the local MMR state diverges from network state. **The transaction is still submitted successfully** - the panic happens during post-transaction sync.

The example prints midenscan links before syncing so you can verify results even if sync fails.

## Dependencies

- Miden SDK v0.12
- Tokio async runtime
- Connects to Miden testnet
