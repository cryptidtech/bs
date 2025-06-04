//! Common tests between web and native

use crate::peer::DefaultBsPeer;
use crate::{peer::BsPeer, Error};
use ::cid::Cid;
use blockstore::Blockstore as BlockstoreTrait;
use blockstore::InMemoryBlockstore;
use bs::params::vlad::FirstEntryKeyParams;
use bs::params::vlad::VladParams;
use bs::update::OpParams;
use bs::{
    config::sync::{KeyManager, MultiSigner},
    params::anykey::PubkeyParams,
};
use bs_traits::CondSync;
use bs_wallets::memory::InMemoryKeyManager;
use multicid::cid;
use multicodec::Codec;
use multihash::mh;
use multikey::mk;
use provenance_log::Key;
use provenance_log::Script;
use provenance_log::{entry::Field, key::key_paths::ValidatedKeyParams as _};

/// Basic test fixture without network capabilities
pub struct TestFixture {
    pub peer: BsPeer<InMemoryKeyManager<Error>, InMemoryBlockstore<64>>,
    pub lock_script: String,
    pub unlock_script: String,
}

/// Test fixture with network capabilities
pub struct NetworkTestFixture {
    pub peer: DefaultBsPeer<InMemoryKeyManager<Error>>,
    pub lock_script: String,
    pub unlock_script: String,
}

impl<KP, BS> BsPeer<KP, BS>
where
    KP: KeyManager<Error> + MultiSigner<Error> + CondSync,
    BS: BlockstoreTrait + CondSync,
{
    /// Helper to create CID from the same parameters for testing
    pub async fn verify_cid_stored(
        &self,
        version: Codec,
        target: Codec,
        hash: Codec,
        data: &[u8],
    ) -> Result<bool, Error> {
        // Create CID
        let multi_cid = cid::Builder::new(version)
            .with_target_codec(target)
            .with_hash(&mh::Builder::new_from_bytes(hash, data)?.try_build()?)
            .try_build()?;

        // Convert to cid::Cid
        let multi_cid_bytes: Vec<u8> = multi_cid.into();
        let cid = Cid::try_from(multi_cid_bytes)?;

        // Check if stored in blockstore
        let result = self.blockstore().has(&cid).await?;
        Ok(result)
    }
}

/// Creates test scripts to be used in test fixtures
fn create_test_scripts() -> (String, String) {
    let entry_key = Field::ENTRY;
    let proof_key = Field::PROOF;
    let pubkey = PubkeyParams::KEY_PATH;

    let unlock_script = format!(
        r#"
         // push the serialized Entry as the message
         push("{entry_key}");

         // push the proof data
         push("{proof_key}");
    "#
    );

    let lock_script = format!(
        r#"
            // then check a possible threshold sig...
            check_signature("/recoverykey", "{entry_key}") ||

            // then check a possible pubkey sig...
            check_signature("{pubkey}", "{entry_key}") ||
            
            // then the pre-image proof...
            check_preimage("/hash")
        "#
    );

    (lock_script, unlock_script)
}

pub async fn setup_test_peer() -> TestFixture {
    // Set up key manager
    let key_manager = InMemoryKeyManager::<Error>::default();

    // Create an in-memory blockstore
    let blockstore = InMemoryBlockstore::<64>::new();

    // Create peer with the in-memory blockstore
    let peer = BsPeer::with_blockstore(key_manager, blockstore);

    let (lock_script, unlock_script) = create_test_scripts();

    TestFixture {
        peer,
        lock_script,
        unlock_script,
    }
}

/// Setup a peer with network capabilities
pub async fn setup_network_test_peer() -> Result<NetworkTestFixture, Error> {
    // Set up key manager
    let key_manager = InMemoryKeyManager::<Error>::default();

    // Create a network-enabled peer
    let peer = DefaultBsPeer::new(key_manager).await?;

    let (lock_script, unlock_script) = create_test_scripts();

    Ok(NetworkTestFixture {
        peer,
        lock_script,
        unlock_script,
    })
}

pub async fn setup_initialized_peer() -> TestFixture {
    let mut fixture = setup_test_peer().await;

    // Initialize the peer
    let res = fixture
        .peer
        .generate(&fixture.lock_script, &fixture.unlock_script)
        .await;
    debug_assert!(res.is_ok(), "Expected successful creation of peer");
    fixture
}

/// Setup an initialized peer with network capabilities
pub async fn setup_initialized_network_peer() -> Result<NetworkTestFixture, Error> {
    let mut fixture = setup_network_test_peer().await?;

    // Initialize the peer
    let res = fixture
        .peer
        .generate(&fixture.lock_script, &fixture.unlock_script)
        .await;

    if let Err(e) = res {
        tracing::error!("Failed to initialize network peer: {:?}", e);
        return Err(e);
    }

    Ok(fixture)
}

pub async fn run_basic_test() {
    tracing::info!("Starting basic_test");
    tracing::debug!("Initializing key manager and peer");

    let seed: [u8; 32] = [42; 32];
    let codec = Codec::Ed25519Priv;
    let _mk = mk::Builder::new_from_seed(codec, &seed)
        .unwrap()
        .try_build()
        .unwrap();

    let mut fixture = setup_test_peer().await;

    // Now we create the peer with valid scripts
    let res = fixture
        .peer
        .generate(&fixture.lock_script, &fixture.unlock_script)
        .await;

    // Check if the creation was successful
    assert!(res.is_ok(), "Expected successful creation of peer");

    // Check if the plog is initialized
    assert!(
        fixture.peer.plog().is_some(),
        "Expected plog to be initialized"
    );

    // Check if the plog can be verified
    let plog = fixture.peer.plog();
    let verify_iter = &mut plog.as_ref().unwrap().verify();
    for result in verify_iter {
        if let Err(e) = result {
            panic!("Plog verification failed: {}", e);
        }
    }
}

/// Test basic peer initialization with network capabilities
pub async fn run_basic_network_test() {
    tracing::info!("Starting basic network test");

    // Create a networked peer
    let mut fixture = setup_network_test_peer()
        .await
        .expect("Should create network peer");

    // Generate with valid scripts
    let res = fixture
        .peer
        .generate(&fixture.lock_script, &fixture.unlock_script)
        .await;

    // Check if creation was successful
    assert!(res.is_ok(), "Expected successful creation of network peer");

    // Verify network client exists
    assert!(
        fixture.peer.network_client.is_some(),
        "Network client should be present"
    );

    // Verify events channel exists
    assert!(
        fixture.peer.events.is_some(),
        "Events channel should be present"
    );

    // Verify PeerId exists
    assert!(fixture.peer.peer_id.is_some(), "PeerId should be present");

    // Check if the plog is initialized
    assert!(
        fixture.peer.plog().is_some(),
        "Expected plog to be initialized in network peer"
    );

    // Check if the plog can be verified
    let plog = fixture.peer.plog();
    let verify_iter = &mut plog.as_ref().unwrap().verify();
    for result in verify_iter {
        if let Err(e) = result {
            panic!("Plog verification failed in network peer: {}", e);
        }
    }
}

// Add more shared test functions here
pub async fn run_in_memory_blockstore_test() {
    tracing::info!("Starting in_memory_blockstore_test");

    let mut fixture = setup_test_peer().await;

    // Create test data
    let test_data = b"test data".to_vec();

    let hash = Codec::Sha2256;
    let target = Codec::Raw;
    let version = Codec::Cidv1;

    // Create the peer with scripts and with CIDs to store
    // Add some OpParams::CidGen entries to test blockstore storage
    // This is a bit awkward:
    // We're stating the PubkeyParams here, yet
    // the actual key is in the wallet. Would be better if one came from the other, yeah?
    let config = bs::open::Config::builder()
        .vlad(VladParams::<FirstEntryKeyParams>::default())
        .pubkey(
            PubkeyParams::builder()
                .codec(Codec::Ed25519Priv)
                .build()
                .into(),
        )
        .entrykey(
            FirstEntryKeyParams::builder()
                .codec(Codec::Ed25519Priv)
                .build()
                .into(),
        )
        .lock(Script::Code(Key::default(), fixture.lock_script.clone()))
        .unlock(Script::Code(Key::default(), fixture.unlock_script.clone()))
        .additional_ops(vec![OpParams::CidGen {
            key: Key::try_from("/test/image/").unwrap(),
            version,
            target,
            hash,
            inline: true,
            data: test_data.clone(),
        }])
        .build();

    // Create peer with this config
    let res = fixture.peer.generate_with_config(config).await;

    match &res {
        Ok(_) => tracing::info!("create_with_config succeeded"),
        Err(e) => tracing::error!("create_with_config failed: {:?}", e),
    }

    assert!(res.is_ok(), "Expected successful creation of peer");

    // verify the plog
    let plog = fixture.peer.plog();
    let verify_iter = &mut plog.as_ref().unwrap().verify();
    for result in verify_iter {
        if let Err(e) = result {
            tracing::error!("Plog verification failed: {}", e);
            panic!("Plog verification failed: {}", e);
        }
    }

    // Verify the CID was stored
    let stored = fixture
        .peer
        .verify_cid_stored(version, target, hash, &test_data)
        .await
        .unwrap();

    assert!(stored, "CID should be stored in blockstore");

    // If you want to verify the actual data:
    let multi_cid = cid::Builder::new(version)
        .with_target_codec(target)
        .with_hash(
            &mh::Builder::new_from_bytes(hash, &test_data)
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    let multi_cid_bytes: Vec<u8> = multi_cid.into();
    let cid = Cid::try_from(multi_cid_bytes).unwrap();

    let stored_data = fixture.peer.blockstore().get(&cid).await.unwrap();
    assert!(stored_data.is_some(), "Data should be in blockstore");
    assert_eq!(
        stored_data.unwrap(),
        test_data,
        "Stored data should match original"
    );
}

/// Test data storage in a network-enabled peer's blockstore
pub async fn run_network_blockstore_test() {
    tracing::info!("Starting network blockstore test");

    let mut fixture = setup_network_test_peer()
        .await
        .expect("Should create network peer");

    // Create test data
    let test_data = b"network test data".to_vec();

    let hash = Codec::Sha2256;
    let target = Codec::Raw;
    let version = Codec::Cidv1;

    // Create a config with CID to store
    let config = bs::open::Config::builder()
        .vlad(VladParams::<FirstEntryKeyParams>::default())
        .pubkey(
            PubkeyParams::builder()
                .codec(Codec::Ed25519Priv)
                .build()
                .into(),
        )
        .entrykey(
            FirstEntryKeyParams::builder()
                .codec(Codec::Ed25519Priv)
                .build()
                .into(),
        )
        .lock(Script::Code(Key::default(), fixture.lock_script.clone()))
        .unlock(Script::Code(Key::default(), fixture.unlock_script.clone()))
        .additional_ops(vec![OpParams::CidGen {
            key: Key::try_from("/network/test/data/").unwrap(),
            version,
            target,
            hash,
            inline: true,
            data: test_data.clone(),
        }])
        .build();

    // Create peer with this config
    let res = fixture.peer.generate_with_config(config).await;
    assert!(
        res.is_ok(),
        "Expected successful creation of network peer with CID"
    );

    // Verify the CID was stored
    let stored = fixture
        .peer
        .verify_cid_stored(version, target, hash, &test_data)
        .await
        .unwrap();

    assert!(stored, "CID should be stored in network peer blockstore");

    // Create multicid and verify data
    let multi_cid = cid::Builder::new(version)
        .with_target_codec(target)
        .with_hash(
            &mh::Builder::new_from_bytes(hash, &test_data)
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    let multi_cid_bytes: Vec<u8> = multi_cid.into();
    let cid = Cid::try_from(multi_cid_bytes).unwrap();

    let stored_data = fixture.peer.blockstore().get(&cid).await.unwrap();
    assert!(
        stored_data.is_some(),
        "Data should be in network peer blockstore"
    );
    assert_eq!(
        stored_data.unwrap(),
        test_data,
        "Retrieved data from network peer should match original"
    );
}

pub async fn run_store_entries_test() {
    // init_logger();
    tracing::info!("Starting test_store_entries");

    let fixture = setup_initialized_peer().await;

    // The peer is initialized, so store_entries has already been called
    // Let's verify the stored entries

    // Get the first lock CID from the plog for verification
    let plog = fixture.peer.plog();
    let first_lock_cid = plog.as_ref().unwrap().vlad.cid();
    let first_lock_cid_bytes: Vec<u8> = first_lock_cid.clone().into();
    let cid = Cid::try_from(first_lock_cid_bytes).unwrap();

    // Verify first lock is in blockstore
    let stored_first_lock = fixture.peer.blockstore().has(&cid).await.unwrap();
    assert!(
        stored_first_lock,
        "First lock should be stored in blockstore"
    );

    // Verify we can retrieve the first lock data
    let first_lock_data = fixture.peer.blockstore().get(&cid).await.unwrap();
    assert!(
        first_lock_data.is_some(),
        "First lock data should be retrievable"
    );

    // Verify each entry is stored in the blockstore
    for (multi_cid, _) in plog.as_ref().unwrap().entries.iter() {
        let multi_cid_bytes: Vec<u8> = multi_cid.clone().into();
        let entry_cid = Cid::try_from(multi_cid_bytes).unwrap();

        let stored_entry = fixture.peer.blockstore().has(&entry_cid).await.unwrap();
        assert!(stored_entry, "Entry should be stored in blockstore");

        let entry_data = fixture.peer.blockstore().get(&entry_cid).await.unwrap();
        assert!(entry_data.is_some(), "Entry data should be retrievable");
    }
}

/// Test storing entries in a network-enabled peer
pub async fn run_network_store_entries_test() {
    tracing::info!("Starting network_store_entries_test");

    let fixture = setup_initialized_network_peer()
        .await
        .expect("Should create initialized network peer");

    // Get the first lock CID from the plog for verification
    let plog = fixture.peer.plog();
    let first_lock_cid = plog.as_ref().unwrap().vlad.cid();
    let first_lock_cid_bytes: Vec<u8> = first_lock_cid.clone().into();
    let cid = Cid::try_from(first_lock_cid_bytes).unwrap();

    // Verify first lock is in blockstore
    let stored_first_lock = fixture.peer.blockstore().has(&cid).await.unwrap();
    assert!(
        stored_first_lock,
        "First lock should be stored in network peer blockstore"
    );

    // Verify we can retrieve the first lock data
    let first_lock_data = fixture.peer.blockstore().get(&cid).await.unwrap();
    assert!(
        first_lock_data.is_some(),
        "First lock data should be retrievable from network peer"
    );

    // Verify each entry is stored in the blockstore
    for (multi_cid, _) in plog.as_ref().unwrap().entries.iter() {
        let multi_cid_bytes: Vec<u8> = multi_cid.clone().into();
        let entry_cid = Cid::try_from(multi_cid_bytes).unwrap();

        let stored_entry = fixture.peer.blockstore().has(&entry_cid).await.unwrap();
        assert!(
            stored_entry,
            "Entry should be stored in network peer blockstore"
        );

        let entry_data = fixture.peer.blockstore().get(&entry_cid).await.unwrap();
        assert!(
            entry_data.is_some(),
            "Entry data should be retrievable from network peer"
        );
    }
}

pub async fn run_update_test() {
    tracing::info!("Starting update_test");

    // Setup peer with initial configuration
    let mut fixture = setup_initialized_peer().await;

    // Create some new data to update with
    let new_data = b"updated data".to_vec();
    let hash = Codec::Sha2256;
    let target = Codec::Raw;
    let version = Codec::Cidv1;

    // Create an update configuration
    let update_config = bs::update::Config::builder()
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .unlock(Script::Code(Key::default(), fixture.unlock_script.clone()))
        .additional_ops(vec![OpParams::CidGen {
            key: Key::try_from("/test/updated/").unwrap(),
            version,
            target,
            hash,
            inline: true,
            data: new_data.clone(),
        }])
        .build();

    // Apply the update
    let res = fixture.peer.update(update_config).await;
    assert!(res.is_ok(), "Expected successful update");

    // Verify the update was stored
    let stored = fixture
        .peer
        .verify_cid_stored(version, target, hash, &new_data)
        .await
        .unwrap();

    assert!(stored, "Updated CID should be stored in blockstore");

    // Verify plog is still valid after update
    let plog = fixture.peer.plog();
    let verify_iter = &mut plog.as_ref().unwrap().verify();
    for result in verify_iter {
        if let Err(e) = result {
            panic!("Plog verification failed after update: {}", e);
        }
    }
}

/// Test updating a network-enabled peer
pub async fn run_network_update_test() {
    tracing::info!("Starting network_update_test");

    // Setup initialized network peer
    let mut fixture = setup_initialized_network_peer()
        .await
        .expect("Should create initialized network peer");

    // Create update data
    let new_data = b"network updated data".to_vec();
    let hash = Codec::Sha2256;
    let target = Codec::Raw;
    let version = Codec::Cidv1;

    // Create update config
    let update_config = bs::update::Config::builder()
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .unlock(Script::Code(Key::default(), fixture.unlock_script.clone()))
        .additional_ops(vec![OpParams::CidGen {
            key: Key::try_from("/network/test/updated/").unwrap(),
            version,
            target,
            hash,
            inline: true,
            data: new_data.clone(),
        }])
        .build();

    // Apply the update
    let res = fixture.peer.update(update_config).await;
    assert!(res.is_ok(), "Expected successful update of network peer");

    // Verify the update was stored
    let stored = fixture
        .peer
        .verify_cid_stored(version, target, hash, &new_data)
        .await
        .unwrap();

    assert!(
        stored,
        "Updated CID should be stored in network peer blockstore"
    );

    // Verify plog is still valid
    let plog = fixture.peer.plog();
    let verify_iter = &mut plog.as_ref().unwrap().verify();
    for result in verify_iter {
        if let Err(e) = result {
            panic!("Network peer plog verification failed after update: {}", e);
        }
    }
}

pub async fn run_load_test() {
    tracing::info!("Starting load_test");

    // Setup an initialized peer to get a valid plog
    let fixture = setup_initialized_peer().await;

    // Get the plog from the initialized peer
    let original_plog = fixture.peer.plog().unwrap().clone();

    // Create a new peer with empty state
    let mut new_fixture = setup_test_peer().await;

    // Ensure the new peer has no plog yet
    assert!(
        new_fixture.peer.plog().is_none(),
        "New peer should have no plog initially"
    );

    // Load the plog into the new peer
    let res = new_fixture.peer.load(original_plog.clone()).await;
    assert!(res.is_ok(), "Expected successful loading of plog");

    // Verify the plog was loaded
    assert!(
        new_fixture.peer.plog().is_some(),
        "Plog should now be loaded"
    );

    // Verify the loaded plog has the correct data
    let loaded_plog = new_fixture.peer.plog().unwrap();
    assert_eq!(
        loaded_plog.vlad.cid(),
        original_plog.vlad.cid(),
        "Loaded plog should have same first lock CID"
    );
    assert_eq!(
        loaded_plog.entries.len(),
        original_plog.entries.len(),
        "Loaded plog should have same number of entries"
    );

    // Verify the loaded plog can be verified
    let verify_iter = &mut loaded_plog.verify();
    for result in verify_iter {
        if let Err(e) = result {
            panic!("Loaded plog verification failed: {}", e);
        }
    }

    // Verify that entries were stored in the blockstore during load
    // Check first lock CID
    let first_lock_cid = loaded_plog.vlad.cid();
    let first_lock_cid_bytes: Vec<u8> = first_lock_cid.clone().into();
    let cid = Cid::try_from(first_lock_cid_bytes).unwrap();
    let has_first_lock = new_fixture.peer.blockstore().has(&cid).await.unwrap();
    assert!(
        has_first_lock,
        "First lock should be in blockstore after load"
    );

    // Check entries
    for (multi_cid, _) in loaded_plog.entries.iter() {
        let multi_cid_bytes: Vec<u8> = multi_cid.clone().into();
        let entry_cid = Cid::try_from(multi_cid_bytes).unwrap();
        let has_entry = new_fixture.peer.blockstore().has(&entry_cid).await.unwrap();
        assert!(has_entry, "Entry should be in blockstore after load");
    }
}

/// Test loading a plog into a network-enabled peer
pub async fn run_network_load_test() {
    tracing::info!("Starting network_load_test");

    // Setup an initialized peer to get a valid plog
    let fixture = setup_initialized_peer().await;

    // Get the plog from the initialized peer
    let original_plog = fixture.peer.plog().unwrap().clone();

    // Create a new network peer with empty state
    let mut new_fixture = setup_network_test_peer()
        .await
        .expect("Should create new network peer");

    // Ensure the new network peer has no plog yet
    assert!(
        new_fixture.peer.plog().is_none(),
        "New network peer should have no plog initially"
    );

    // Load the plog into the new network peer
    let res = new_fixture.peer.load(original_plog.clone()).await;
    assert!(
        res.is_ok(),
        "Expected successful loading of plog into network peer"
    );

    // Verify the plog was loaded
    assert!(
        new_fixture.peer.plog().is_some(),
        "Plog should now be loaded in network peer"
    );

    // Verify the loaded plog has the correct data
    let loaded_plog = new_fixture.peer.plog().unwrap();
    assert_eq!(
        loaded_plog.vlad.cid(),
        original_plog.vlad.cid(),
        "Loaded plog in network peer should have same first lock CID"
    );

    // Verify entries were stored in blockstore
    let first_lock_cid = loaded_plog.vlad.cid();
    let first_lock_cid_bytes: Vec<u8> = first_lock_cid.clone().into();
    let cid = Cid::try_from(first_lock_cid_bytes).unwrap();
    let has_first_lock = new_fixture.peer.blockstore().has(&cid).await.unwrap();
    assert!(
        has_first_lock,
        "First lock should be in network peer blockstore after load"
    );
}

pub async fn run_peer_initialization_test() {
    tracing::info!("Starting peer initialization test");

    // Initialize key manager for the peer
    let key_manager = InMemoryKeyManager::<Error>::default();

    // Create a new peer with the default platform blockstore
    let peer_result = DefaultBsPeer::new(key_manager).await;

    match &peer_result {
        Ok(_) => tracing::info!("Peer initialization succeeded"),
        Err(e) => tracing::error!("Peer initialization failed: {:?}", e),
    }

    // Check that peer creation succeeded
    assert!(peer_result.is_ok(), "Peer should initialize successfully");

    let peer = peer_result.unwrap();

    // Check if network client was established
    assert!(
        peer.network_client.as_ref().is_some(),
        "Network client should be initialized"
    );
    assert!(peer.events.is_some(), "Event channel should be initialized");

    // Verify we have a working blockstore
    let blockstore = peer.blockstore();

    // Try to store and retrieve some data to verify blockstore works
    let test_cid =
        Cid::try_from("bafkreihwsnuregceqh263vgdathcprnbvatyat6h6mu7ipjhhodcdbyhg4").unwrap();
    let test_data = b"test network initialization".to_vec();

    let put_result = blockstore.put_keyed(&test_cid, &test_data).await;
    assert!(
        put_result.is_ok(),
        "Should be able to store data in blockstore"
    );

    let get_result = blockstore.get(&test_cid).await;
    assert!(
        get_result.is_ok(),
        "Should be able to retrieve data from blockstore"
    );
    assert_eq!(
        get_result.unwrap().unwrap(),
        test_data,
        "Retrieved data should match stored data"
    );
}

/// Test network functionality of the peer
pub async fn run_network_functionality_test() {
    tracing::info!("Starting network functionality test");

    // Create a network-enabled peer
    let peer_result = setup_network_test_peer().await;
    assert!(peer_result.is_ok(), "Should create network-enabled peer");

    let fixture = peer_result.unwrap();

    // Verify network components are initialized
    assert!(
        fixture.peer.network_client.is_some(),
        "Network client should be initialized"
    );
    assert!(
        fixture.peer.events.is_some(),
        "Event channel should be initialized"
    );
    assert!(
        fixture.peer.peer_id.is_some(),
        "Peer ID should be initialized"
    );

    // Verify peer ID is valid
    let peer_id = fixture.peer.peer_id.unwrap();
    tracing::info!("Network peer has PeerId: {}", peer_id);

    // Store some data in blockstore and verify network client can access it
    let test_data = b"network test functionality".to_vec();
    let test_cid =
        Cid::try_from("bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku").unwrap();

    // Store data in blockstore
    let put_result = fixture
        .peer
        .blockstore()
        .put_keyed(&test_cid, &test_data)
        .await;
    assert!(put_result.is_ok(), "Should store data successfully");

    // Verify data is retrievable
    let has_result = fixture.peer.blockstore().has(&test_cid).await;
    assert!(
        has_result.is_ok() && has_result.unwrap(),
        "Data should be in blockstore"
    );

    // Retrieve and verify data
    let get_result = fixture.peer.blockstore().get(&test_cid).await;
    assert!(get_result.is_ok(), "Should retrieve data successfully");
    assert_eq!(
        get_result.unwrap().unwrap(),
        test_data,
        "Retrieved data should match stored data"
    );
}

/// Test that resolver works with network client
pub async fn run_resolver_test() {
    tracing::info!("Starting resolver test");

    // Create network peer
    let peer_result = setup_network_test_peer().await;
    assert!(
        peer_result.is_ok(),
        "Should create network peer for resolver test"
    );

    let fixture = peer_result.unwrap();

    // Create a multicid for testing
    let test_data = b"resolver test data".to_vec();
    let hash = Codec::Sha2256;
    let target = Codec::Raw;
    let version = Codec::Cidv1;

    let multi_cid = cid::Builder::new(version)
        .with_target_codec(target)
        .with_hash(
            &mh::Builder::new_from_bytes(hash, &test_data)
                .unwrap()
                .try_build()
                .unwrap(),
        )
        .try_build()
        .unwrap();

    // Convert to cid::Cid and store in blockstore
    let multi_cid_bytes: Vec<u8> = multi_cid.clone().into();
    let cid = Cid::try_from(multi_cid_bytes).unwrap();

    let put_result = fixture.peer.blockstore().put_keyed(&cid, &test_data).await;
    assert!(put_result.is_ok(), "Should store data for resolver test");

    // The resolver functionality is tested in integration/e2e tests since it requires
    // actual network interaction between peers to fully verify
    tracing::info!("Resolver test setup complete - actual resolver functionality would be tested in integration tests");
}
