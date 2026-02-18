//! PSWAP Simple Partial Fill (No Fees, v0.13)
//!
//! Stripped-down test of the basic PSWAP partial swap on Miden testnet.
//! No fee oracle, no treasury, no FPI — just the core swap logic.
//!
//! 1. Creates faucets + wallets (all on-chain)
//! 2. Maker creates PSWAP: offers 100,000 GOLD for 100,000 SILVER
//! 3. Taker fills 25%: sends 25,000 SILVER, receives 25,000 GOLD
//! 4. P2ID note created with 25,000 SILVER for maker
//! 5. Leftover PSWAP note created with 75,000 GOLD (still owned by maker)
//! 6. Maker consumes P2ID note to receive 25,000 SILVER
//!
//! Run with: cargo run --example pswap_simple

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

use miden_client::store::AccountRecordData;
use miden_client::{
    account::component::{BasicFungibleFaucet, BasicWallet},
    auth::AuthSecretKey,
    builder::ClientBuilder,
    keystore::FilesystemKeyStore,
    note::{
        build_p2id_recipient, build_swap_tag, Note, NoteAssets, NoteInputs, NoteMetadata,
        NoteRecipient, NoteTag, NoteType,
    },
    rpc::{Endpoint, GrpcClient},
    transaction::{OutputNote, TransactionRequestBuilder},
    Felt, Word, ZERO,
};
use miden_client_sqlite_store::ClientBuilderSqliteExt;
use miden_protocol::{
    account::{AccountBuilder, AccountId, AccountStorageMode, AccountType},
    asset::{Asset, FungibleAsset, TokenSymbol},
    crypto::hash::rpo::Rpo256 as Hasher,
    note::NoteDetails,
};
use miden_standards::account::auth::AuthFalcon512Rpo;
use rand::RngCore;

const OFFERED_AMOUNT: u64 = 100_000;
const REQUESTED_AMOUNT: u64 = 100_000;
const FILL_AMOUNT: u64 = 25_000; // 25% fill
const POLL_INTERVAL_SECS: u64 = 5;
const MAX_POLL_ATTEMPTS: u32 = 24;

fn log_prefix_suffix(name: &str, id: AccountId) {
    let hex = id.to_hex();
    let prefix: u64 = id.prefix().into();
    let suffix: u64 = id.suffix().into();
    println!("  {} ID:     {}", name, hex);
    println!("  {} prefix:  {} (0x{:016x})", name, prefix, prefix);
    println!("  {} suffix:  {} (0x{:016x})", name, suffix, suffix);
}

/// Create a PSWAP note with 14 inputs (no fee/treasury)
///
/// Inputs (14 felts):
///   0-3:   REQUESTED_ASSET_WORD [amount, 0, suffix, prefix]
///   4:     SWAPP_TAG
///   5:     P2ID_TAG
///   6-7:   PARENT_SERIAL_0, PARENT_SERIAL_1
///   8:     SWAP_COUNT
///   9:     EXPIRATION_BLOCK (0 = no expiration)
///   10-11: PARENT_SERIAL_2, PARENT_SERIAL_3
///   12:    CREATOR_PREFIX
///   13:    CREATOR_SUFFIX
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
) -> Result<Note> {
    let swapp_tag = build_swap_tag(note_type, &offered_asset, &requested_asset);
    let p2id_tag = NoteTag::with_account_target(creator_id);
    let requested_asset_word: Word = requested_asset.into();

    let creator_prefix: u64 = creator_id.prefix().into();
    let creator_suffix: u64 = creator_id.suffix().into();

    let ps = parent_serial.unwrap_or([ZERO, ZERO, ZERO, ZERO].into());

    let inputs_vec = vec![
        requested_asset_word[0],   // 0: requested amount
        requested_asset_word[1],   // 1: zero
        requested_asset_word[2],   // 2: faucet suffix
        requested_asset_word[3],   // 3: faucet prefix
        Felt::from(swapp_tag),     // 4: swapp tag
        Felt::from(p2id_tag),      // 5: p2id tag
        ps[0],                     // 6: parent_serial[0]
        ps[1],                     // 7: parent_serial[1]
        Felt::new(swap_count),     // 8: swap count
        ZERO,                      // 9: expiration (0 = no expiration)
        ps[2],                     // 10: parent_serial[2]
        ps[3],                     // 11: parent_serial[3]
        Felt::new(creator_prefix), // 12: creator prefix
        Felt::new(creator_suffix), // 13: creator suffix
    ];

    println!("\n=== NOTE INPUTS ({}) ===", inputs_vec.len());
    for (i, input) in inputs_vec.iter().enumerate() {
        println!(
            "  input[{:2}]: {:20} (0x{:016x})",
            i,
            input.as_int(),
            input.as_int()
        );
    }

    let note_inputs = NoteInputs::new(inputs_vec)?;
    let metadata = NoteMetadata::new(last_consumer_id, note_type, swapp_tag);
    let assets = NoteAssets::new(vec![offered_asset])?;
    let recipient = NoteRecipient::new(serial_num, note_script.clone(), note_inputs);

    Ok(Note::new(assets, metadata, recipient))
}

fn compute_p2id_serial_num(swap_serial_num: Word, swap_count: u64) -> Word {
    let swap_count_word: Word = [Felt::new(swap_count), ZERO, ZERO, ZERO].into();
    Hasher::merge(&[swap_serial_num.into(), swap_count_word.into()]).into()
}

fn create_leftover_pswap_note(
    creator_id: AccountId,
    consumer_id: AccountId,
    leftover_offered: Asset,
    leftover_requested: Asset,
    swap_count: u64,
    note_script: &miden_client::note::NoteScript,
    original_serial: Word,
    note_type: NoteType,
) -> Result<Note> {
    let leftover_serial: Word = [
        original_serial[0],
        original_serial[1],
        original_serial[2],
        Felt::new(u64::from(original_serial[3]) + 1),
    ]
    .into();

    create_pswap_note(
        creator_id,
        consumer_id,
        leftover_offered,
        leftover_requested,
        leftover_serial,
        swap_count,
        note_script,
        note_type,
        Some(original_serial),
    )
}

fn create_p2id_note_with_serial(
    sender_id: AccountId,
    target_id: AccountId,
    assets: Vec<Asset>,
    serial_num: Word,
) -> Result<Note> {
    let note_type = NoteType::Public;
    let tag = NoteTag::with_account_target(target_id);
    let recipient = build_p2id_recipient(target_id, serial_num)?;
    let metadata = NoteMetadata::new(sender_id, note_type, tag);
    let note_assets = NoteAssets::new(assets)?;

    Ok(Note::new(note_assets, metadata, recipient))
}

#[tokio::main]
async fn main() -> Result<()> {
    println!("\n============================================================");
    println!("PSWAP SIMPLE PARTIAL FILL (NO FEES, v0.13)");
    println!("============================================================");

    // Setup unique directory per run
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis();
    let test_dir = std::env::temp_dir().join(format!("pswap_simple_{}", timestamp));
    std::fs::create_dir_all(&test_dir)?;
    let store_path = test_dir.join("store.sqlite3");
    let keystore_path = test_dir.join("keystore");
    std::fs::create_dir_all(&keystore_path)?;

    println!("\nStore: {:?}", store_path);
    println!("Keystore: {:?}", keystore_path);

    // Create client
    let endpoint = Endpoint::testnet();
    let rpc = Arc::new(GrpcClient::new(&endpoint, 30_000));
    let keystore = Arc::new(FilesystemKeyStore::new(keystore_path.clone())?);

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
    let gold_key = AuthSecretKey::new_falcon512_rpo();
    let gold_faucet_account = AccountBuilder::new(seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthFalcon512Rpo::new(gold_key.public_key().to_commitment()))
        .with_component(BasicFungibleFaucet::new(
            TokenSymbol::new("GOLD")?,
            0,
            Felt::new(1_000_000_000),
        )?)
        .build()?;
    let gold_faucet = gold_faucet_account.id();
    client.add_account(&gold_faucet_account, false).await?;
    keystore.add_key(&gold_key)?;

    println!("\n=== GOLD FAUCET ===");
    log_prefix_suffix("GOLD", gold_faucet);

    // SILVER faucet
    client.rng().fill_bytes(&mut seed);
    let silver_key = AuthSecretKey::new_falcon512_rpo();
    let silver_faucet_account = AccountBuilder::new(seed)
        .account_type(AccountType::FungibleFaucet)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthFalcon512Rpo::new(
            silver_key.public_key().to_commitment(),
        ))
        .with_component(BasicFungibleFaucet::new(
            TokenSymbol::new("SILVER")?,
            0,
            Felt::new(1_000_000_000),
        )?)
        .build()?;
    let silver_faucet = silver_faucet_account.id();
    client.add_account(&silver_faucet_account, false).await?;
    keystore.add_key(&silver_key)?;

    println!("\n=== SILVER FAUCET ===");
    log_prefix_suffix("SILVER", silver_faucet);

    // =========================================================================
    // PHASE 2: Create Wallets
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 2: CREATE WALLETS");
    println!("============================================================");

    // Maker wallet
    client.rng().fill_bytes(&mut seed);
    let maker_key = AuthSecretKey::new_falcon512_rpo();
    let maker_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthFalcon512Rpo::new(
            maker_key.public_key().to_commitment(),
        ))
        .with_component(BasicWallet)
        .build()?;
    let maker_id = maker_account.id();
    client.add_account(&maker_account, false).await?;
    keystore.add_key(&maker_key)?;

    println!("\n=== MAKER ===");
    log_prefix_suffix("Maker", maker_id);

    // Taker wallet
    client.rng().fill_bytes(&mut seed);
    let taker_key = AuthSecretKey::new_falcon512_rpo();
    let taker_account = AccountBuilder::new(seed)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_auth_component(AuthFalcon512Rpo::new(
            taker_key.public_key().to_commitment(),
        ))
        .with_component(BasicWallet)
        .build()?;
    let taker_id = taker_account.id();
    client.add_account(&taker_account, false).await?;
    keystore.add_key(&taker_key)?;

    println!("\n=== TAKER ===");
    log_prefix_suffix("Taker", taker_id);

    // =========================================================================
    // PHASE 3: Mint Tokens
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 3: MINT TOKENS");
    println!("============================================================");

    // Mint GOLD to maker
    println!("\nMinting {} GOLD to Maker...", OFFERED_AMOUNT);
    let gold_asset = FungibleAsset::new(gold_faucet, OFFERED_AMOUNT)?;
    let mint_req = TransactionRequestBuilder::new().build_mint_fungible_asset(
        gold_asset,
        maker_id,
        NoteType::Public,
        client.rng(),
    )?;
    client.submit_new_transaction(gold_faucet, mint_req).await?;

    // Mint SILVER to taker
    println!("Minting {} SILVER to Taker...", FILL_AMOUNT);
    let silver_asset = FungibleAsset::new(silver_faucet, FILL_AMOUNT)?;
    let mint_req = TransactionRequestBuilder::new().build_mint_fungible_asset(
        silver_asset,
        taker_id,
        NoteType::Public,
        client.rng(),
    )?;
    client
        .submit_new_transaction(silver_faucet, mint_req)
        .await?;

    // Wait for mints to commit
    println!("\nWaiting for mints to commit (30s)...");
    sleep(Duration::from_secs(30)).await;
    client.sync_state().await?;

    // Consume minted notes
    println!("\n--- Consuming Minted Notes ---");

    let maker_notes = client.get_consumable_notes(Some(maker_id)).await?;
    if !maker_notes.is_empty() {
        let notes: Vec<Note> = maker_notes
            .into_iter()
            .map(|(n, _)| n.try_into().unwrap())
            .collect();
        let req = TransactionRequestBuilder::new().build_consume_notes(notes)?;
        client.submit_new_transaction(maker_id, req).await?;
        println!("  Maker consumed mint note(s)");
    }

    let taker_notes = client.get_consumable_notes(Some(taker_id)).await?;
    if !taker_notes.is_empty() {
        let notes: Vec<Note> = taker_notes
            .into_iter()
            .map(|(n, _)| n.try_into().unwrap())
            .collect();
        let req = TransactionRequestBuilder::new().build_consume_notes(notes)?;
        client.submit_new_transaction(taker_id, req).await?;
        println!("  Taker consumed mint note(s)");
    }

    println!("\nWaiting for consumption to commit (30s)...");
    sleep(Duration::from_secs(30)).await;
    client.sync_state().await?;

    // =========================================================================
    // PHASE 4: Create PSWAP Note
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 4: CREATE PSWAP NOTE");
    println!("============================================================");
    println!(
        "\nOffer: {} GOLD for {} SILVER (1:1 ratio)",
        OFFERED_AMOUNT, REQUESTED_AMOUNT
    );

    let mut pswap_code = std::fs::read_to_string("masm/notes/pswap.masm")?;

    // Derive the P2ID script root from the same SDK helper used for expected P2ID notes,
    // then inject it into pswap.masm so script lookup cannot drift across crate versions.
    let root_probe_serial: Word = [ZERO, ZERO, ZERO, ZERO].into();
    let p2id_probe_recipient = build_p2id_recipient(maker_id, root_probe_serial)?;
    let p2id_root = p2id_probe_recipient.script().root();
    let p2id_root_words = [
        p2id_root[0].as_int(),
        p2id_root[1].as_int(),
        p2id_root[2].as_int(),
        p2id_root[3].as_int(),
    ];
    println!(
        "SDK P2ID root words: [{} {} {} {}]",
        p2id_root_words[0], p2id_root_words[1], p2id_root_words[2], p2id_root_words[3]
    );

    let mut lines: Vec<String> = pswap_code.lines().map(|l| l.to_string()).collect();
    let mut injected = false;
    for i in 1..lines.len() {
        if lines[i].contains("mem_storew_be.P2ID_SCRIPT_ROOT_WORD dropw") {
            let prev_trimmed = lines[i - 1].trim_start();
            if prev_trimmed.starts_with("push.") {
                let indent: String = lines[i - 1]
                    .chars()
                    .take_while(|c| c.is_whitespace())
                    .collect();
                lines[i - 1] = format!(
                    "{indent}push.{}.{}.{}.{}",
                    p2id_root_words[0], p2id_root_words[1], p2id_root_words[2], p2id_root_words[3]
                );
                injected = true;
                break;
            }
        }
    }
    if !injected {
        return Err(anyhow::anyhow!(
            "Failed to inject P2ID root into pswap.masm (could not find push before mem_storew_be.P2ID_SCRIPT_ROOT_WORD)"
        ));
    }
    pswap_code = lines.join("\n");

    let note_script = client
        .code_builder()
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
        None,
    )?;
    let swapp_tag = swapp_note.metadata().tag();
    let swapp_note_id = swapp_note.id();

    println!("\n=== PSWAP NOTE CREATED ===");
    println!("  Note ID: {}", swapp_note_id.to_hex());
    println!("  Tag: {:?}", swapp_tag);

    // Register tags for discovery
    client.add_note_tag(swapp_tag).await?;
    let p2id_tag = NoteTag::with_account_target(maker_id);
    client.add_note_tag(p2id_tag).await?;

    // Submit SWAPP creation
    let req = TransactionRequestBuilder::new()
        .own_output_notes(vec![OutputNote::Full(swapp_note.clone())])
        .build()?;
    client.submit_new_transaction(maker_id, req).await?;
    println!("  SWAPP transaction submitted");

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
        if found {
            break;
        }
        println!("  Polling {}/{}...", attempt, MAX_POLL_ATTEMPTS);
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
    if !found {
        return Err(anyhow::anyhow!(
            "SWAPP note not consumable after {} attempts",
            MAX_POLL_ATTEMPTS
        ));
    }

    // =========================================================================
    // PHASE 5: Taker Fills 25%
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 5: TAKER FILLS 25%");
    println!("============================================================");

    let sync = client.sync_state().await?;
    println!("  Block: {}", sync.block_num);

    let taker_receives = (FILL_AMOUNT * OFFERED_AMOUNT) / REQUESTED_AMOUNT;
    let leftover_offered = OFFERED_AMOUNT - taker_receives;
    let leftover_requested = REQUESTED_AMOUNT - FILL_AMOUNT;

    println!("\nFill calculation:");
    println!("  Fill amount:        {} SILVER (taker sends)", FILL_AMOUNT);
    println!("  Maker receives:     {} SILVER", FILL_AMOUNT);
    println!("  Taker receives:     {} GOLD", taker_receives);
    println!(
        "  Leftover offered:   {} GOLD (in new SWAPP)",
        leftover_offered
    );
    println!(
        "  Leftover requested: {} SILVER (in new SWAPP)",
        leftover_requested
    );

    // Note args: [0, 0, 0, fill_amount]
    let note_args: Word = [
        Felt::new(0),
        Felt::new(0),
        Felt::new(0),
        Felt::new(FILL_AMOUNT),
    ]
    .into();

    // Compute expected P2ID to maker
    let next_swap_count = 1u64;
    let p2id_serial = compute_p2id_serial_num(swap_serial_num, next_swap_count);
    let p2id_asset = Asset::Fungible(FungibleAsset::new(silver_faucet, FILL_AMOUNT)?);
    let expected_p2id =
        create_p2id_note_with_serial(taker_id, maker_id, vec![p2id_asset], p2id_serial)?;
    let expected_p2id_id = expected_p2id.id();
    println!(
        "\nExpected Maker P2ID Note ID: {}",
        expected_p2id_id.to_hex()
    );

    // Compute expected leftover SWAPP
    let leftover_offered_asset =
        Asset::Fungible(FungibleAsset::new(gold_faucet, leftover_offered)?);
    let leftover_requested_asset =
        Asset::Fungible(FungibleAsset::new(silver_faucet, leftover_requested)?);

    let expected_leftover = create_leftover_pswap_note(
        maker_id,
        taker_id,
        leftover_offered_asset,
        leftover_requested_asset,
        next_swap_count,
        &note_script,
        swap_serial_num,
        NoteType::Public,
    )?;
    let expected_leftover_id = expected_leftover.id();
    println!(
        "Expected Leftover Note ID: {}",
        expected_leftover_id.to_hex()
    );

    // Build and submit fill transaction
    let req = TransactionRequestBuilder::new()
        .input_notes([(swapp_note.clone(), Some(note_args))])
        .expected_future_notes(vec![
            (
                NoteDetails::from(expected_p2id.clone()),
                expected_p2id.metadata().tag(),
            ),
            (
                NoteDetails::from(expected_leftover.clone()),
                expected_leftover.metadata().tag(),
            ),
        ])
        .expected_output_recipients(vec![
            expected_p2id.recipient().clone(),
            expected_leftover.recipient().clone(),
        ])
        .build()?;

    println!("\n--- Submitting Fill Transaction ---");
    let tx_result = client.submit_new_transaction(taker_id, req).await?;
    println!("  Transaction ID: {:?}", tx_result);

    // Print midenscan links
    println!("\n============================================================");
    println!("MIDENSCAN LINKS");
    println!("============================================================");
    println!(
        "  Maker:    https://testnet.midenscan.com/account/{}",
        maker_id.to_hex()
    );
    println!(
        "  Taker:    https://testnet.midenscan.com/account/{}",
        taker_id.to_hex()
    );
    println!(
        "  P2ID:     https://testnet.midenscan.com/note/{}",
        expected_p2id_id.to_hex()
    );
    println!(
        "  Leftover: https://testnet.midenscan.com/note/{}",
        expected_leftover_id.to_hex()
    );

    // Wait and sync
    println!("\nWaiting for fill to commit (45s)...");
    sleep(Duration::from_secs(45)).await;

    match client.sync_state().await {
        Ok(sync_result) => println!("  Sync OK, block: {}", sync_result.block_num),
        Err(e) => {
            println!("  Sync error: {:?}", e);
            println!("  Check midenscan links above.");
            return Ok(());
        }
    }

    // =========================================================================
    // PHASE 6: Maker Consumes P2ID
    // =========================================================================
    println!("\n============================================================");
    println!("PHASE 6: MAKER CONSUMES P2ID");
    println!("============================================================");

    let mut p2id_consumed = false;
    for attempt in 1..=MAX_POLL_ATTEMPTS {
        client.sync_state().await?;
        let consumable = client.get_consumable_notes(Some(maker_id)).await?;
        for (note, _) in &consumable {
            if note.id() == expected_p2id_id {
                println!("  P2ID consumable after {} attempts", attempt);
                let note_obj: Note = note.clone().try_into().unwrap();
                let req = TransactionRequestBuilder::new().build_consume_notes(vec![note_obj])?;
                client.submit_new_transaction(maker_id, req).await?;
                p2id_consumed = true;
                break;
            }
        }
        if p2id_consumed {
            break;
        }
        println!("  Polling {}/{}...", attempt, MAX_POLL_ATTEMPTS);
        sleep(Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }

    if p2id_consumed {
        println!("\nWaiting for P2ID consumption (30s)...");
        sleep(Duration::from_secs(30)).await;
        client.sync_state().await?;
    }

    // =========================================================================
    // PHASE 7: Verify
    // =========================================================================
    println!("\n============================================================");
    println!("FINAL BALANCES");
    println!("============================================================");

    if let Ok(Some(r)) = client.get_account(maker_id).await {
        if let AccountRecordData::Full(acct) = r.account_data() {
            let v = acct.vault();
            println!(
                "  Maker:  GOLD={}, SILVER={} (expected 0, {})",
                v.get_balance(gold_faucet).unwrap_or(0),
                v.get_balance(silver_faucet).unwrap_or(0),
                FILL_AMOUNT
            );
        }
    }

    if let Ok(Some(r)) = client.get_account(taker_id).await {
        if let AccountRecordData::Full(acct) = r.account_data() {
            let v = acct.vault();
            println!(
                "  Taker:  GOLD={}, SILVER={} (expected {}, 0)",
                v.get_balance(gold_faucet).unwrap_or(0),
                v.get_balance(silver_faucet).unwrap_or(0),
                taker_receives
            );
        }
    }

    println!(
        "  Leftover SWAPP: {} GOLD (note {})",
        leftover_offered,
        expected_leftover_id.to_hex()
    );

    println!("\nDone.");
    Ok(())
}
