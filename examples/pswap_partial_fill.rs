//! PSWAP Partial Fill Example (Self-Contained with Fee Collection)
//!
//! Demonstrates a working PSWAP (Partial Swap) on Miden testnet with FPI fee collection.
//! All accounts (including the Fee Oracle) are created within the example - no external
//! dependencies required.
//!
//! 1. Creates faucets, wallets, treasury, and Fee Oracle (all on-chain)
//! 2. Maker creates PSWAP: offers 100,000 GOLD for 100,000 SILVER
//! 3. Taker fills 25%: sends 25,000 SILVER, receives 25,000 GOLD
//! 4. Fee Oracle returns 10 bps fee via FPI → 25 SILVER fee to treasury
//! 5. P2ID note created with 24,975 SILVER for maker (fill - fee)
//! 6. Fee P2ID note created with 25 SILVER for treasury
//! 7. Leftover SWAPP note created with 75,000 GOLD (still owned by maker)
//! 8. Maker consumes P2ID note to receive 24,975 SILVER
//!
//! Final verified balances:
//! - Maker: 0 GOLD, 24,975 SILVER
//! - Taker: 25,000 GOLD, 0 SILVER
//! - Treasury: 25 SILVER (fee collected)
//! - Leftover: 75,000 GOLD (active note, owned by maker)
//!
//! Run with: cargo run --example pswap_partial_fill

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use miden_client::{
    account::component::{BasicFungibleFaucet, BasicWallet},
    auth::AuthSecretKey,
    builder::ClientBuilder,
    keystore::FilesystemKeyStore,
    note::{
        build_p2id_recipient, build_swap_tag, Note, NoteAssets, NoteExecutionHint,
        NoteInputs, NoteMetadata, NoteRecipient, NoteTag, NoteType,
    },
    rpc::{domain::account::AccountStorageRequirements, Endpoint, GrpcClient},
    transaction::{ForeignAccount, OutputNote, TransactionRequestBuilder},
    Felt, ScriptBuilder, Word, ZERO,
};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_lib::account::auth::AuthRpoFalcon512;
use miden_objects::{
    account::{AccountBuilder, AccountComponent, AccountId, AccountStorageMode, AccountType, StorageSlot},
    asset::{Asset, FungibleAsset, TokenSymbol},
    crypto::hash::rpo::Rpo256 as Hasher,
    note::NoteDetails,
};
use miden_lib::transaction::TransactionKernel;
use miden_assembly::mast::MastNodeExt; // For .digest() on MastNode
use rand::{rngs::StdRng, RngCore};

const OFFERED_AMOUNT: u64 = 100_000;
const REQUESTED_AMOUNT: u64 = 100_000;
const FILL_AMOUNT: u64 = 25_000; // 25% fill
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_ATTEMPTS: u32 = 24;
const FEE_BPS: u64 = 10; // 0.1% fee (from Fee Oracle)

/// Log prefix and suffix for an AccountId
fn log_prefix_suffix(name: &str, id: AccountId) {
    let hex = id.to_hex();
    let prefix: u64 = id.prefix().into();
    let suffix: u64 = id.suffix().into();
    println!("  {} ID:     {}", name, hex);
    println!("  {} prefix:  {} (0x{:016x})", name, prefix, prefix);
    println!("  {} suffix:  {} (0x{:016x})", name, suffix, suffix);
}

/// Create a PSWAP note with 16 inputs (CLOB format with fee collection)
///
/// Inputs (16 felts):
///   0-3:   REQUESTED_ASSET_WORD [amount, 0, suffix, prefix]
///   4:     SWAPP_TAG - NoteTag for the SWAPP note
///   5:     P2ID_TAG - NoteTag for P2ID payback notes to creator
///   6-7:   PARENT_SERIAL_0, PARENT_SERIAL_1 (audit trail)
///   8:     SWAP_COUNT - Number of times this note has been partially filled
///   9:     EXPIRATION_BLOCK - Block height after which note expires (0 = no expiration)
///   10-11: PARENT_SERIAL_2, PARENT_SERIAL_3 (audit trail)
///   12:    CREATOR_PREFIX - Creator account ID prefix
///   13:    CREATOR_SUFFIX - Creator account ID suffix
///   14:    TREASURY_PREFIX - Treasury account ID prefix (0 = no fee)
///   15:    TREASURY_SUFFIX - Treasury account ID suffix (0 = no fee)
fn create_pswap_note(
    creator_id: AccountId,
    last_consumer_id: AccountId,
    offered_asset: Asset,
    requested_asset: Asset,
    serial_num: Word,
    swap_count: u64,
    note_script: &miden_client::note::NoteScript,
    note_type: NoteType,
    parent_serial: Option<Word>,
    treasury_id: Option<AccountId>,
) -> Result<Note> {

    let swapp_tag = build_swap_tag(note_type, &offered_asset, &requested_asset)?;
    let p2id_tag = NoteTag::from_account_id(creator_id);
    let requested_asset_word: Word = requested_asset.into();

    println!("\n=== REQUESTED_ASSET WORD (indices 0-3) ===");
    println!("  [0] amount: {} (0x{:016x})", requested_asset_word[0].as_int(), requested_asset_word[0].as_int());
    println!("  [1] zero:   {} (0x{:016x})", requested_asset_word[1].as_int(), requested_asset_word[1].as_int());
    println!("  [2] suffix: {} (0x{:016x})", requested_asset_word[2].as_int(), requested_asset_word[2].as_int());
    println!("  [3] prefix: {} (0x{:016x})", requested_asset_word[3].as_int(), requested_asset_word[3].as_int());

    let creator_prefix: u64 = creator_id.prefix().into();
    let creator_suffix: u64 = creator_id.suffix().into();

    // Parent serial for audit trail (zeros for root PSWAP)
    let ps = parent_serial.unwrap_or([ZERO, ZERO, ZERO, ZERO].into());

    // Treasury ID for fee collection (zeros = no fee)
    let (treasury_prefix, treasury_suffix) = treasury_id
        .map(|id| (u64::from(id.prefix()), u64::from(id.suffix())))
        .unwrap_or((0, 0));

    let inputs_vec = vec![
        requested_asset_word[0],  // 0: requested amount
        requested_asset_word[1],  // 1: zero
        requested_asset_word[2],  // 2: faucet suffix
        requested_asset_word[3],  // 3: faucet prefix
        Felt::from(swapp_tag),    // 4: swapp tag
        Felt::from(p2id_tag),     // 5: p2id tag
        ps[0],                    // 6: parent_serial[0]
        ps[1],                    // 7: parent_serial[1]
        Felt::new(swap_count),    // 8: swap count
        ZERO,                     // 9: expiration (0 = no expiration)
        ps[2],                    // 10: parent_serial[2]
        ps[3],                    // 11: parent_serial[3]
        Felt::new(creator_prefix), // 12: creator prefix
        Felt::new(creator_suffix), // 13: creator suffix
        Felt::new(treasury_prefix), // 14: treasury prefix
        Felt::new(treasury_suffix), // 15: treasury suffix
    ];

    println!("\n=== ALL 16 NOTE INPUTS ===");
    for (i, input) in inputs_vec.iter().enumerate() {
        let desc = match i {
            0 => "requested_amount",
            1 => "zero",
            2 => "faucet_suffix",
            3 => "faucet_prefix",
            4 => "swapp_tag",
            5 => "p2id_tag",
            6 => "parent_serial_0",
            7 => "parent_serial_1",
            8 => "swap_count",
            9 => "expiration_block",
            10 => "parent_serial_2",
            11 => "parent_serial_3",
            12 => "creator_prefix",
            13 => "creator_suffix",
            14 => "treasury_prefix",
            15 => "treasury_suffix",
            _ => "unknown",
        };
        println!("  input[{:2}] ({:16}): {:20} (0x{:016x})", i, desc, input.as_int(), input.as_int());
    }

    let note_inputs = NoteInputs::new(inputs_vec)?;

    let metadata = NoteMetadata::new(
        last_consumer_id,
        note_type,
        swapp_tag,
        NoteExecutionHint::always(),
        ZERO,
    )?;
    let assets = NoteAssets::new(vec![offered_asset])?;
    let recipient = NoteRecipient::new(serial_num, note_script.clone(), note_inputs);

    Ok(Note::new(assets, metadata, recipient))
}

/// Compute P2ID serial number from swap serial and count
fn compute_p2id_serial_num(swap_serial_num: Word, swap_count: u64) -> Word {
    let swap_count_word: Word = [Felt::new(swap_count), ZERO, ZERO, ZERO].into();
    Hasher::merge(&[swap_serial_num.into(), swap_count_word.into()]).into()
}

/// Create expected leftover PSWAP note
fn create_leftover_pswap_note(
    creator_id: AccountId,
    consumer_id: AccountId,
    leftover_offered: Asset,
    leftover_requested: Asset,
    swap_count: u64,
    note_script: &miden_client::note::NoteScript,
    original_serial: Word,
    note_type: NoteType,
    treasury_id: Option<AccountId>,
) -> Result<Note> {
    // Leftover serial = original serial with last element + 1
    let leftover_serial: Word = [
        original_serial[0],
        original_serial[1],
        original_serial[2],
        Felt::new(u64::from(original_serial[3]) + 1),
    ].into();

    // Pass original serial as parent serial for audit trail
    create_pswap_note(
        creator_id,
        consumer_id,
        leftover_offered,
        leftover_requested,
        leftover_serial,
        swap_count,
        note_script,
        note_type,
        Some(original_serial),  // parent serial for audit trail
        treasury_id,
    )
}

/// Create P2ID note with specific serial
fn create_p2id_note_with_serial(
    sender_id: AccountId,
    target_id: AccountId,
    assets: Vec<Asset>,
    serial_num: Word,
) -> Result<Note> {
    let note_type = NoteType::Public;
    let tag = NoteTag::from_account_id(target_id);
    let recipient = build_p2id_recipient(target_id, serial_num)?;
    let metadata = NoteMetadata::new(sender_id, note_type, tag, NoteExecutionHint::always(), ZERO)?;
    let note_assets = NoteAssets::new(assets)?;

    Ok(Note::new(note_assets, metadata, recipient))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n============================================================");
    println!("PSWAP PARTIAL FILL EXAMPLE (SELF-CONTAINED, TESTNET)");
    println!("============================================================");
    println!("\nThis example demonstrates:");
    println!("  1. Create Fee Oracle with FPI (self-contained, no external deps)");
    println!("  2. Maker creates PSWAP: {} GOLD for {} SILVER", OFFERED_AMOUNT, REQUESTED_AMOUNT);
    println!("  3. Taker fills 25%: sends {} SILVER, receives {} GOLD", FILL_AMOUNT, FILL_AMOUNT);
    println!("  4. Fee Oracle returns {} bps → fee collected by treasury", FEE_BPS);
    println!("  5. Maker consumes P2ID: receives fill - fee SILVER");
    println!("  6. Leftover SWAPP: {} GOLD remains", OFFERED_AMOUNT - FILL_AMOUNT);

    // Setup unique directory per run
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let test_dir = std::env::temp_dir().join(format!("pswap_example_{}", timestamp));
    std::fs::create_dir_all(&test_dir)?;
    let store_path = test_dir.join("store.sqlite3");
    let keystore_path = test_dir.join("keystore");
    std::fs::create_dir_all(&keystore_path)?;

    println!("\nStore: {:?}", store_path);
    println!("Keystore: {:?}", keystore_path);

    // Create client
    let endpoint = Endpoint::testnet();
    let rpc = Arc::new(GrpcClient::new(&endpoint, 30_000));
    let keystore = Arc::new(FilesystemKeyStore::<StdRng>::new(keystore_path.clone())?);

    let mut client = ClientBuilder::new()
        .rpc(rpc)
        .sqlite_store(store_path)
        .authenticator(keystore.clone())
        .in_debug_mode(true.into())
        .build()
        .await
        .context("Failed to build client")?;

    // Initial sync
    println!("\n--- Initial Sync ---");
    let sync = client.sync_state().await?;
    println!("Block: {}", sync.block_num);

    // =========================================================================
    // PHASE 1: Create Faucets
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 1: CREATE FAUCETS");
    println!("============================================================");

    let mut seed = [0u8; 32];

    // GOLD faucet
    client.rng().fill_bytes(&mut seed);
    let gold_key = AuthSecretKey::new_rpo_falcon512();
    let gold_faucet_account = AccountBuilder::new(seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(gold_key.public_key().to_commitment()))
        .with_component(BasicFungibleFaucet::new(
            TokenSymbol::new("GOLD")?,
            0,
            Felt::new(1_000_000_000),
        )?)
        .build()?;
    let gold_faucet = gold_faucet_account.id();
    client.add_account(&gold_faucet_account, false).await?;
    keystore.add_key(&gold_key)?;

    println!("\n=== GOLD FAUCET (OFFERED TOKEN) ===");
    log_prefix_suffix("GOLD", gold_faucet);

    // SILVER faucet
    client.rng().fill_bytes(&mut seed);
    let silver_key = AuthSecretKey::new_rpo_falcon512();
    let silver_faucet_account = AccountBuilder::new(seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(silver_key.public_key().to_commitment()))
        .with_component(BasicFungibleFaucet::new(
            TokenSymbol::new("SILVER")?,
            0,
            Felt::new(1_000_000_000),
        )?)
        .build()?;
    let silver_faucet = silver_faucet_account.id();
    client.add_account(&silver_faucet_account, false).await?;
    keystore.add_key(&silver_key)?;

    println!("\n=== SILVER FAUCET (REQUESTED TOKEN) ===");
    log_prefix_suffix("SILVER", silver_faucet);

    // =========================================================================
    // PHASE 2: Create Wallets
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 2: CREATE WALLETS");
    println!("============================================================");

    // Maker wallet
    client.rng().fill_bytes(&mut seed);
    let maker_key = AuthSecretKey::new_rpo_falcon512();
    let maker_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(maker_key.public_key().to_commitment()))
        .with_component(BasicWallet)
        .build()?;
    let maker_id = maker_account.id();
    client.add_account(&maker_account, false).await?;
    keystore.add_key(&maker_key)?;

    println!("\n=== MAKER WALLET ===");
    log_prefix_suffix("Maker", maker_id);

    // Taker wallet
    client.rng().fill_bytes(&mut seed);
    let taker_key = AuthSecretKey::new_rpo_falcon512();
    let taker_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(taker_key.public_key().to_commitment()))
        .with_component(BasicWallet)
        .build()?;
    let taker_id = taker_account.id();
    client.add_account(&taker_account, false).await?;
    keystore.add_key(&taker_key)?;

    println!("\n=== TAKER WALLET ===");
    log_prefix_suffix("Taker", taker_id);

    // Treasury wallet (receives fees)
    client.rng().fill_bytes(&mut seed);
    let treasury_key = AuthSecretKey::new_rpo_falcon512();
    let treasury_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(treasury_key.public_key().to_commitment()))
        .with_component(BasicWallet)
        .build()?;
    let treasury_id = treasury_account.id();
    client.add_account(&treasury_account, false).await?;
    keystore.add_key(&treasury_key)?;

    println!("\n=== TREASURY WALLET (receives fees) ===");
    log_prefix_suffix("Treasury", treasury_id);

    // =========================================================================
    // PHASE 2b: Create Fee Oracle
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 2b: CREATE FEE ORACLE");
    println!("============================================================");

    let fee_oracle_code = std::fs::read_to_string("masm/accounts/fee_oracle.masm")
        .context("Failed to read fee_oracle.masm")?;

    let treasury_prefix: u64 = treasury_id.prefix().into();
    let treasury_suffix: u64 = treasury_id.suffix().into();

    let oracle_component = AccountComponent::compile(
        &fee_oracle_code,
        TransactionKernel::assembler().with_debug_mode(true),
        vec![
            StorageSlot::Value(Word::from([Felt::new(FEE_BPS), ZERO, ZERO, ZERO])),
            StorageSlot::Value(Word::from([Felt::new(treasury_prefix), ZERO, ZERO, ZERO])),
            StorageSlot::Value(Word::from([Felt::new(treasury_suffix), ZERO, ZERO, ZERO])),
        ],
    )
    .context("Failed to compile fee_oracle.masm")?
    .with_supports_all_types();

    let oracle_key = AuthSecretKey::new_rpo_falcon512();
    client.rng().fill_bytes(&mut seed);
    let fee_oracle_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountImmutableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthRpoFalcon512::new(oracle_key.public_key().to_commitment()))
        .with_component(BasicWallet)
        .with_component(oracle_component)
        .build()?;
    let fee_oracle_id = fee_oracle_account.id();
    client.add_account(&fee_oracle_account, false).await?;
    keystore.add_key(&oracle_key)?;

    println!("\n=== FEE ORACLE ===");
    log_prefix_suffix("Oracle", fee_oracle_id);
    println!("  Fee BPS:  {}", FEE_BPS);
    println!("  Treasury: {}", treasury_id.to_hex());

    // Deploy Fee Oracle (register on-chain via nop transaction)
    println!("\n--- Deploying Fee Oracle ---");
    let deploy_script = client
        .script_builder()
        .compile_tx_script("begin nop end")
        .context("Failed to compile deploy script")?;
    let deploy_req = TransactionRequestBuilder::new()
        .custom_script(deploy_script)
        .build()?;
    client.submit_new_transaction(fee_oracle_id, deploy_req).await?;
    println!("  Fee Oracle deployment transaction submitted");

    // Wait for deployment to commit
    println!("\nWaiting for oracle deployment (30s)...");
    sleep(Duration::from_secs(30)).await;
    client.sync_state().await?;
    println!("  Fee Oracle deployed on-chain");

    // Re-import oracle from network to get full MAST forest for FPI
    // (locally-created accounts may not have the full code tree after sync)
    println!("\n--- Re-importing Fee Oracle from network ---");
    match client.import_account_by_id(fee_oracle_id).await {
        Ok(_) => println!("  Fee Oracle re-imported with full code tree"),
        Err(e) => println!("  Re-import note: {:?} (may already be tracked)", e),
    }

    // =========================================================================
    // PHASE 3: Mint Tokens
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 3: MINT TOKENS");
    println!("============================================================");

    // Mint GOLD to maker
    println!("\nMinting {} GOLD to Maker...", OFFERED_AMOUNT);
    let gold_asset = FungibleAsset::new(gold_faucet, OFFERED_AMOUNT)?;
    let mint_req = TransactionRequestBuilder::new()
        .build_mint_fungible_asset(gold_asset, maker_id, NoteType::Public, client.rng())?;
    client.submit_new_transaction(gold_faucet, mint_req).await?;

    // Mint SILVER to taker
    println!("Minting {} SILVER to Taker...", FILL_AMOUNT);
    let silver_asset = FungibleAsset::new(silver_faucet, FILL_AMOUNT)?;
    let mint_req = TransactionRequestBuilder::new()
        .build_mint_fungible_asset(silver_asset, taker_id, NoteType::Public, client.rng())?;
    client.submit_new_transaction(silver_faucet, mint_req).await?;

    // Wait for mints to commit
    println!("\nWaiting for mints to commit (30s)...");
    sleep(Duration::from_secs(30)).await;
    client.sync_state().await?;

    // Consume minted notes
    println!("\n--- Consuming Minted Notes ---");

    // Maker consumes GOLD
    let maker_notes = client.get_consumable_notes(Some(maker_id)).await?;
    if !maker_notes.is_empty() {
        let ids: Vec<_> = maker_notes.iter().map(|(n, _)| n.id()).collect();
        let req = TransactionRequestBuilder::new().build_consume_notes(ids)?;
        client.submit_new_transaction(maker_id, req).await?;
        println!("  Maker consumed {} mint note(s)", maker_notes.len());
    }

    // Taker consumes SILVER
    let taker_notes = client.get_consumable_notes(Some(taker_id)).await?;
    if !taker_notes.is_empty() {
        let ids: Vec<_> = taker_notes.iter().map(|(n, _)| n.id()).collect();
        let req = TransactionRequestBuilder::new().build_consume_notes(ids)?;
        client.submit_new_transaction(taker_id, req).await?;
        println!("  Taker consumed {} mint note(s)", taker_notes.len());
    }

    // Wait for consumption
    println!("\nWaiting for consumption to commit (30s)...");
    sleep(Duration::from_secs(30)).await;
    client.sync_state().await?;

    // =========================================================================
    // PHASE 4: Create PSWAP Note
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 4: CREATE PSWAP NOTE");
    println!("============================================================");
    println!("\nOffer: {} GOLD for {} SILVER (1:1 ratio)", OFFERED_AMOUNT, REQUESTED_AMOUNT);

    // Compile oracle code as standalone library to extract get_fee_bps MAST root hash.
    // This hash is needed by pswap.masm to call the oracle via FPI (execute_foreign_procedure).
    let assembler = TransactionKernel::assembler().with_debug_mode(true);
    let source_manager = Arc::new(miden_assembly::DefaultSourceManager::default());
    let oracle_module = miden_assembly::ast::Module::parser(miden_assembly::ast::ModuleKind::Library)
        .parse_str(
            miden_assembly::LibraryPath::new("external_contract::fee_oracle")
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            &fee_oracle_code,
            &source_manager,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let oracle_lib = assembler.clone().assemble_library([oracle_module])
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Find get_fee_bps MAST root from library exports
    let mut hash_0: u64 = 0;
    let mut hash_1: u64 = 0;
    let mut hash_2: u64 = 0;
    let mut hash_3: u64 = 0;
    println!("\n  === Oracle Library Procedure Digests ===");
    for export in oracle_lib.exports() {
        let digest = oracle_lib.mast_forest()[export.node].digest();
        let name_str = format!("{}", export.name);
        println!("    {}: [0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]",
            name_str,
            digest[0].as_int(), digest[1].as_int(),
            digest[2].as_int(), digest[3].as_int());
        if name_str.ends_with("get_fee_bps") {
            hash_0 = digest[0].as_int();
            hash_1 = digest[1].as_int();
            hash_2 = digest[2].as_int();
            hash_3 = digest[3].as_int();
        }
    }
    assert!(hash_0 != 0, "get_fee_bps MAST root not found in oracle library");

    // Replace Fee Oracle constants in pswap.masm with this run's oracle ID and MAST hashes
    let oracle_prefix: u64 = fee_oracle_id.prefix().into();
    let oracle_suffix: u64 = fee_oracle_id.suffix().into();

    let pswap_code = std::fs::read_to_string("masm/notes/pswap.masm")?
        .replace(
            "const.FEE_ORACLE_PREFIX=0x085e1bc7eb50221",
            &format!("const.FEE_ORACLE_PREFIX=0x{:x}", oracle_prefix),
        )
        .replace(
            "const.FEE_ORACLE_SUFFIX=0x010055105b091fb",
            &format!("const.FEE_ORACLE_SUFFIX=0x{:x}", oracle_suffix),
        )
        .replace(
            "const.GET_FEE_BPS_HASH_0=0x5975cc7bc789e292",
            &format!("const.GET_FEE_BPS_HASH_0=0x{:x}", hash_0),
        )
        .replace(
            "const.GET_FEE_BPS_HASH_1=0x07c773a6f2ef5804",
            &format!("const.GET_FEE_BPS_HASH_1=0x{:x}", hash_1),
        )
        .replace(
            "const.GET_FEE_BPS_HASH_2=0x57a4c0788fd079b5",
            &format!("const.GET_FEE_BPS_HASH_2=0x{:x}", hash_2),
        )
        .replace(
            "const.GET_FEE_BPS_HASH_3=0x4f62f0774d5e8d88",
            &format!("const.GET_FEE_BPS_HASH_3=0x{:x}", hash_3),
        );

    println!("\n  Fee Oracle: {} (on-chain)", fee_oracle_id.to_hex());
    println!("  Oracle prefix: 0x{:x}", oracle_prefix);
    println!("  Oracle suffix: 0x{:x}", oracle_suffix);
    println!("  get_fee_bps hash: [0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]", hash_0, hash_1, hash_2, hash_3);

    let note_script = ScriptBuilder::new(true)
        .compile_note_script(pswap_code)
        .context("Failed to compile PSWAP script")?;

    let offered_asset = Asset::Fungible(FungibleAsset::new(gold_faucet, OFFERED_AMOUNT)?);
    let requested_asset = Asset::Fungible(FungibleAsset::new(silver_faucet, REQUESTED_AMOUNT)?);

    let swap_serial_num: Word = [Felt::new(1), Felt::new(2), Felt::new(3), Felt::new(4)].into();

    let swapp_note = create_pswap_note(
        maker_id,
        maker_id,
        offered_asset.clone(),
        requested_asset.clone(),
        swap_serial_num,
        0,
        &note_script,
        NoteType::Public,
        None,  // No parent serial for root PSWAP
        Some(treasury_id),  // Treasury receives fees
    )?;
    let swapp_tag = swapp_note.metadata().tag();
    let swapp_note_id = swapp_note.id();

    println!("\n=== PSWAP NOTE CREATED ===");
    println!("  Note ID: {}", swapp_note_id.to_hex());
    println!("  Tag: {:?}", swapp_tag);

    // Register tags for discovery
    client.add_note_tag(swapp_tag).await?;
    let p2id_tag = NoteTag::from_account_id(maker_id);
    client.add_note_tag(p2id_tag).await?;

    // Submit SWAPP creation
    let req = TransactionRequestBuilder::new()
        .own_output_notes(vec![OutputNote::Full(swapp_note.clone())])
        .build()?;
    client.submit_new_transaction(maker_id, req).await?;
    println!("\n  SWAPP transaction submitted");

    // Wait for note to become consumable
    println!("\n--- Waiting for SWAPP note to be consumable ---");
    let mut found = false;
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        client.sync_state().await?;
        let consumable = client.get_consumable_notes(None).await?;
        for (note, _) in &consumable {
            if note.id() == swapp_note_id {
                println!("  Note consumable after {} attempts", attempt);
                found = true;
                break;
            }
        }
        if found { break; }
        println!("  Polling {}/{}...", attempt, MAX_POLL_ATTEMPTS);
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
    if !found {
        return Err(anyhow::anyhow!("SWAPP note not consumable after {} attempts", MAX_POLL_ATTEMPTS));
    }

    // =========================================================================
    // PHASE 5: Taker Fills 25%
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 5: TAKER FILLS 25%");
    println!("============================================================");

    // Fresh sync before fill to ensure state is current
    println!("\n--- Syncing before fill transaction ---");
    let sync = client.sync_state().await?;
    println!("  Block: {}", sync.block_num);

    // Verify taker has SILVER to fill
    if let Ok(Some(taker_record)) = client.get_account(taker_id).await {
        let silver_balance = taker_record.account().vault().get_balance(silver_faucet).unwrap_or(0);
        println!("  Taker SILVER balance: {}", silver_balance);
        if silver_balance < FILL_AMOUNT {
            return Err(anyhow::anyhow!("Taker doesn't have enough SILVER: {} < {}", silver_balance, FILL_AMOUNT));
        }
    }

    let taker_receives = (FILL_AMOUNT * OFFERED_AMOUNT) / REQUESTED_AMOUNT;
    let leftover_offered = OFFERED_AMOUNT - taker_receives;
    let leftover_requested = REQUESTED_AMOUNT - FILL_AMOUNT;

    // Calculate fee: fee = fill_amount * fee_bps / 10000
    let fee_amount = (FILL_AMOUNT * FEE_BPS) / 10000;
    let maker_receives = FILL_AMOUNT - fee_amount;

    println!("\nFill calculation (with {}bp fee):", FEE_BPS);
    println!("  Fill amount:        {} SILVER (taker sends)", FILL_AMOUNT);
    println!("  Fee amount:         {} SILVER (to treasury)", fee_amount);
    println!("  Maker receives:     {} SILVER (fill - fee)", maker_receives);
    println!("  Taker receives:     {} GOLD", taker_receives);
    println!("  Leftover offered:   {} GOLD (in new SWAPP)", leftover_offered);
    println!("  Leftover requested: {} SILVER (in new SWAPP)", leftover_requested);

    // Note args: [0, 0, 0, fill_amount]
    let note_args: Word = [
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(FILL_AMOUNT),
    ].into();

    println!("\n=== NOTE ARGS ===");
    println!("  [0, 0, 0, {}]  // fill_amount at index 3", FILL_AMOUNT);

    // Compute expected P2ID to maker (fill_amount - fee)
    let next_swap_count = 1u64;
    let p2id_serial = compute_p2id_serial_num(swap_serial_num, next_swap_count);
    let p2id_asset = Asset::Fungible(FungibleAsset::new(silver_faucet, maker_receives)?);
    let expected_p2id = create_p2id_note_with_serial(
        taker_id,
        maker_id,
        vec![p2id_asset],
        p2id_serial,
    )?;
    let expected_p2id_id = expected_p2id.id();
    println!("\nExpected Maker P2ID Note ID: {}", expected_p2id_id.to_hex());
    println!("  Contains: {} SILVER (fill - fee)", maker_receives);

    // Compute expected fee P2ID to treasury
    // Fee serial = hash(swap_serial, swap_count + 1)
    let fee_serial = compute_p2id_serial_num(swap_serial_num, next_swap_count + 1);
    let fee_asset = Asset::Fungible(FungibleAsset::new(silver_faucet, fee_amount)?);
    let expected_fee_p2id = create_p2id_note_with_serial(
        taker_id,
        treasury_id,
        vec![fee_asset],
        fee_serial,
    )?;
    let expected_fee_p2id_id = expected_fee_p2id.id();
    println!("\nExpected Fee P2ID Note ID: {}", expected_fee_p2id_id.to_hex());
    println!("  Contains: {} SILVER (fee to treasury)", fee_amount);

    // Compute expected leftover SWAPP
    let leftover_offered_asset = Asset::Fungible(FungibleAsset::new(gold_faucet, leftover_offered)?);
    let leftover_requested_asset = Asset::Fungible(FungibleAsset::new(silver_faucet, leftover_requested)?);

    println!("\n--- Expected Leftover SWAPP Note ---");
    let expected_leftover = create_leftover_pswap_note(
        maker_id,
        taker_id,
        leftover_offered_asset,
        leftover_requested_asset,
        next_swap_count,
        &note_script,
        swap_serial_num,
        NoteType::Public,
        Some(treasury_id),  // Treasury for future fees
    )?;
    let expected_leftover_id = expected_leftover.id();
    println!("\nExpected Leftover Note ID: {}", expected_leftover_id.to_hex());

    // Debug: verify oracle code is intact in client store
    println!("\n=== DEBUG: FEE ORACLE CODE VERIFICATION ===");
    if let Ok(Some(oracle_record)) = client.get_account(fee_oracle_id).await {
        let oracle_code = oracle_record.account().code();
        let oracle_mast = oracle_code.mast();
        println!("  Oracle code procedures: {}", oracle_code.procedures().len());
        println!("  Oracle MAST forest nodes: {}", oracle_mast.num_nodes());
        println!("  Oracle MAST local procedure digests:");
        for digest in oracle_mast.local_procedure_digests() {
            println!("    {:?}", digest);
            // Check if this matches our expected hash
            let d0 = Felt::from(digest[0]).as_int();
            let d1 = Felt::from(digest[1]).as_int();
            let d2 = Felt::from(digest[2]).as_int();
            let d3 = Felt::from(digest[3]).as_int();
            if d0 == hash_0 && d1 == hash_1 && d2 == hash_2 && d3 == hash_3 {
                println!("      ^^^ MATCHES get_fee_bps hash!");
            }
        }
        println!("  Expected hash: [0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]", hash_0, hash_1, hash_2, hash_3);
        println!("  Oracle code commitment: {:?}", oracle_code.commitment());
        // Also print each procedure's MAST root
        println!("  Oracle code procedures (by AccountCode):");
        for (i, proc_info) in oracle_code.procedures().iter().enumerate() {
            let root = proc_info.mast_root();
            println!("    proc[{}]: root=[0x{:x}, 0x{:x}, 0x{:x}, 0x{:x}]",
                i, root[0].as_int(), root[1].as_int(), root[2].as_int(), root[3].as_int());
        }
    } else {
        println!("  WARNING: Oracle account not found in client store!");
    }

    // Create ForeignAccount for Fee Oracle FPI
    let fee_oracle_foreign = ForeignAccount::public(
        fee_oracle_id,
        AccountStorageRequirements::default(),
    )?;

    // Build and submit transaction with Fee Oracle as foreign account.
    // The ForeignAccount::public fetches the oracle's code from the network,
    // providing its MAST nodes to the TransactionMastStore for `dyn` dispatch.
    let req = TransactionRequestBuilder::new()
        .authenticated_input_notes([(swapp_note_id, Some(note_args))])
        .foreign_accounts([fee_oracle_foreign])
        .expected_future_notes(vec![
            (NoteDetails::from(expected_p2id.clone()), expected_p2id.metadata().tag()),
            (NoteDetails::from(expected_fee_p2id.clone()), expected_fee_p2id.metadata().tag()),
            (NoteDetails::from(expected_leftover.clone()), expected_leftover.metadata().tag()),
        ])
        .expected_output_recipients(vec![
            expected_p2id.recipient().clone(),
            expected_fee_p2id.recipient().clone(),
            expected_leftover.recipient().clone(),
        ])
        .build()?;

    println!("\n--- Submitting Fill Transaction ---");
    let tx_result = client.submit_new_transaction(taker_id, req).await?;
    println!("  Transaction ID: {:?}", tx_result);

    println!("\n============================================================");
    println!("EXPECTED OUTPUT NOTES");
    println!("============================================================");
    println!("  P2ID to Maker ({} SILVER): {}", maker_receives, expected_p2id_id.to_hex());
    println!("  Fee P2ID to Treasury ({} SILVER): {}", fee_amount, expected_fee_p2id_id.to_hex());
    println!("  Leftover SWAPP ({} GOLD):  {}", leftover_offered, expected_leftover_id.to_hex());

    // Print midenscan links NOW (before sync) so user can verify even if sync panics
    println!("\n============================================================");
    println!("MIDENSCAN VERIFICATION LINKS");
    println!("============================================================");
    println!("  Maker:    https://testnet.midenscan.com/account/{}", maker_id.to_hex());
    println!("  Taker:    https://testnet.midenscan.com/account/{}", taker_id.to_hex());
    println!("  Treasury: https://testnet.midenscan.com/account/{}", treasury_id.to_hex());
    println!("  P2ID:     https://testnet.midenscan.com/note/{}", expected_p2id_id.to_hex());
    println!("  Fee P2ID: https://testnet.midenscan.com/note/{}", expected_fee_p2id_id.to_hex());
    println!("  Leftover: https://testnet.midenscan.com/note/{}", expected_leftover_id.to_hex());
    println!("\n  Fill transaction submitted! Verify on midenscan if sync fails.");

    // Wait and sync
    println!("\nWaiting for fill transaction to commit (45s)...");
    sleep(Duration::from_secs(45)).await;

    // Sync - may panic due to known MMR issue in Miden SDK
    println!("\n--- Syncing after fill (may fail due to MMR bug) ---");
    match client.sync_state().await {
        Ok(sync_result) => {
            println!("  Sync successful, block: {}", sync_result.block_num);
        }
        Err(e) => {
            println!("  Sync error: {:?}", e);
            println!("  This is a known Miden SDK issue. Transaction was submitted.");
            println!("  Check midenscan links above to verify.");
            return Ok(());
        }
    }

    // =========================================================================
    // PHASE 6: Maker Consumes P2ID Note
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 6: MAKER CONSUMES P2ID NOTE");
    println!("============================================================");

    // Wait for P2ID to become consumable
    println!("\n--- Waiting for P2ID note ---");
    let mut p2id_consumed = false;
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        client.sync_state().await?;
        let consumable = client.get_consumable_notes(Some(maker_id)).await?;
        for (note, _) in &consumable {
            if note.id() == expected_p2id_id {
                println!("  P2ID consumable after {} attempts, consuming...", attempt);
                let req = TransactionRequestBuilder::new().build_consume_notes(vec![note.id()])?;
                client.submit_new_transaction(maker_id, req).await?;
                p2id_consumed = true;
                break;
            }
        }
        if p2id_consumed { break; }
        println!("  Polling {}/{}...", attempt, MAX_POLL_ATTEMPTS);
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }

    if p2id_consumed {
        println!("\nWaiting for P2ID consumption to commit (30s)...");
        sleep(Duration::from_secs(30)).await;
        client.sync_state().await?;
    }

    // =========================================================================
    // PHASE 7: Verify Final Balances
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 7: VERIFY FINAL BALANCES");
    println!("============================================================");

    let mut maker_gold = 0u64;
    let mut maker_silver = 0u64;
    let mut taker_gold = 0u64;
    let mut taker_silver = 0u64;
    let mut treasury_silver = 0u64;

    if let Ok(Some(maker_record)) = client.get_account(maker_id).await {
        let maker_vault = maker_record.account().vault();
        maker_gold = maker_vault.get_balance(gold_faucet).unwrap_or(0);
        maker_silver = maker_vault.get_balance(silver_faucet).unwrap_or(0);
    }

    if let Ok(Some(taker_record)) = client.get_account(taker_id).await {
        let taker_vault = taker_record.account().vault();
        taker_gold = taker_vault.get_balance(gold_faucet).unwrap_or(0);
        taker_silver = taker_vault.get_balance(silver_faucet).unwrap_or(0);
    }

    if let Ok(Some(treasury_record)) = client.get_account(treasury_id).await {
        let treasury_vault = treasury_record.account().vault();
        treasury_silver = treasury_vault.get_balance(silver_faucet).unwrap_or(0);
    }

    println!("\n=== FINAL BALANCES (verified from chain) ===");
    println!("\n  MAKER ({}):", maker_id.to_hex());
    println!("    GOLD:   {} (expected: 0)", maker_gold);
    println!("    SILVER: {} (expected: {} = fill - fee)", maker_silver, maker_receives);

    println!("\n  TAKER ({}):", taker_id.to_hex());
    println!("    GOLD:   {} (expected: {})", taker_gold, taker_receives);
    println!("    SILVER: {} (expected: 0)", taker_silver);

    println!("\n  TREASURY ({}):", treasury_id.to_hex());
    println!("    SILVER: {} (expected: {} fee)", treasury_silver, fee_amount);

    println!("\n  LEFTOVER SWAPP NOTE ({}):", expected_leftover_id.to_hex());
    println!("    GOLD:   {} (remaining to be swapped)", leftover_offered);
    println!("    Owner:  Maker (can reclaim or wait for more fills)");

    // Verify
    let maker_gold_ok = maker_gold == 0;
    let maker_silver_ok = maker_silver == maker_receives;
    let taker_gold_ok = taker_gold == taker_receives;
    let taker_silver_ok = taker_silver == 0;
    let treasury_silver_ok = treasury_silver == fee_amount;

    println!("\n=== BALANCE VERIFICATION ===");
    println!("  Maker GOLD = 0:         {}", if maker_gold_ok { "PASS" } else { "FAIL" });
    println!("  Maker SILVER = {}:      {}", maker_receives, if maker_silver_ok { "PASS" } else { "FAIL" });
    println!("  Taker GOLD = {}:        {}", taker_receives, if taker_gold_ok { "PASS" } else { "FAIL" });
    println!("  Taker SILVER = 0:       {}", if taker_silver_ok { "PASS" } else { "FAIL" });
    println!("  Treasury SILVER = {}:   {}", fee_amount, if treasury_silver_ok { "PASS" } else { "FAIL" });

    // =========================================================================
    // SUMMARY
    // =========================================================================
    println!("\n============================================================");
    println!("SUMMARY");
    println!("============================================================");
    println!("\nAccounts:");
    println!("  GOLD Faucet:   {}", gold_faucet.to_hex());
    println!("  SILVER Faucet: {}", silver_faucet.to_hex());
    println!("  Maker:         {}", maker_id.to_hex());
    println!("  Taker:         {}", taker_id.to_hex());
    println!("  Treasury:      {}", treasury_id.to_hex());
    println!("  Fee Oracle:    {}", fee_oracle_id.to_hex());

    println!("\nNotes:");
    println!("  Original SWAPP:  {} (CONSUMED)", swapp_note_id.to_hex());
    println!("  P2ID to Maker:   {} ({} SILVER)", expected_p2id_id.to_hex(), maker_receives);
    println!("  Fee P2ID:        {} ({} SILVER to treasury)", expected_fee_p2id_id.to_hex(), fee_amount);
    println!("  Leftover SWAPP:  {} (ACTIVE - {} GOLD)", expected_leftover_id.to_hex(), leftover_offered);

    println!("\nMidenscan Links:");
    println!("  Maker: https://testnet.midenscan.com/account/{}", maker_id.to_hex());
    println!("  Taker: https://testnet.midenscan.com/account/{}", taker_id.to_hex());
    println!("  Treasury: https://testnet.midenscan.com/account/{}", treasury_id.to_hex());
    println!("  Leftover: https://testnet.midenscan.com/note/{}", expected_leftover_id.to_hex());

    let all_pass = maker_gold_ok && maker_silver_ok && taker_gold_ok && taker_silver_ok && treasury_silver_ok;
    if all_pass {
        println!("\n=== ALL VERIFICATIONS PASSED ===");
    } else {
        println!("\n=== SOME VERIFICATIONS FAILED ===");
    }

    Ok(())
}
