// SPDX-License-Identifier: Apache-2.0
use crate::cidmap::{self, CidMap};
use multikey::EncodedMultikey;

/// The MkMap type that maps Multikey to Cid
pub type MkMap = CidMap<EncodedMultikey>;
/// The MkMap builder
pub type Builder = cidmap::Builder<EncodedMultikey>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cids::Cids;
    use multicid::{cid, Cid};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::{mk, EncodedMultikey, Multikey};
    use multiutil::EncodingInfo;
    use rng::StdRng;
    use std::path::PathBuf;
    use tokio::{fs, test};
    use tracing::{span, Level};

    // returns a random Ed25519 secret key as a Multikey
    fn get_mk() -> EncodedMultikey {
        let mut rng = StdRng::from_os_rng();
        mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build_encoded()
            .unwrap()
    }

    // returns a Cid for the passed in data
    fn get_cid(b: &[u8]) -> Cid {
        cid::Builder::new(Codec::Cidv1)
            .with_target_codec(Codec::Identity)
            .with_hash(
                &mh::Builder::new_from_bytes(Codec::Sha3512, b)
                    .unwrap()
                    .try_build()
                    .unwrap(),
            )
            .try_build()
            .unwrap()
    }

    #[tokio::test]
    async fn test_builder_lazy() {
        let _s = span!(Level::INFO, "test_builder_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap1");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        let vm = Builder::new(&pb).try_build().await.unwrap();
        assert_eq!(vm.0.root, pb);
        assert!(vm.0.lazy);
        assert_eq!(vm.0.base_encoding, Multikey::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        }
    }

    #[tokio::test]
    async fn test_builder_not_lazy() {
        let _s = span!(Level::INFO, "test_builder_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap2");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        let vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();
        assert_eq!(vm.0.root, pb);
        assert!(!vm.0.lazy);
        assert_eq!(vm.0.base_encoding, Multikey::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        let mut dir = fs::read_dir(&pb).await.unwrap();
        while let Some(d) = dir.next_entry().await.unwrap() {
            assert!(d.file_type().await.unwrap().is_dir());
        }

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        }
    }

    #[tokio::test]
    async fn test_put_lazy() {
        let _s = span!(Level::INFO, "test_put_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap3");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");

        // Get subfolder and ensure it exists
        let (_, subfolder, _, _) = vm.0.get_paths(&mk).await.unwrap();
        fs::create_dir_all(&subfolder)
            .await
            .expect("Failed to create subfolder");

        vm.put(&mk, &cid1).await.unwrap();

        // Get with error handling
        let cid2 = vm.get(&mk).await.unwrap();

        assert_eq!(cid1, cid2);

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        }
    }

    #[tokio::test]
    async fn test_put_not_lazy() {
        let _s = span!(Level::INFO, "test_put_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap4");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");

        // Get subfolder and ensure it exists
        let (_, subfolder, _, _) = vm.0.get_paths(&mk).await.unwrap();
        fs::create_dir_all(&subfolder)
            .await
            .expect("Failed to create subfolder");

        // Now put data
        let _ = vm.put(&mk, &cid1).await.unwrap();
        let cid2 = vm.get(&mk).await.unwrap();

        assert_eq!(cid1, cid2);

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        }
    }

    #[tokio::test]
    async fn test_rm_lazy() {
        let _s = span!(Level::INFO, "test_rm_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap5");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");

        // Get subfolder and ensure it exists
        let (_, subfolder, _, _) = vm.0.get_paths(&mk).await.unwrap();
        fs::create_dir_all(&subfolder)
            .await
            .expect("Failed to create subfolder");

        // Now put data
        let _ = vm.put(&mk, &cid1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, _, file, lazy_deleted_file) = vm.0.get_paths(&mk).await.unwrap();

        // lazy delete the block
        let cid2 = vm.rm(&mk).await.unwrap();
        assert_eq!(cid1, cid2);

        // this is lazy so the lazy deleted file should sill be there
        assert!(lazy_deleted_file.try_exists().unwrap());
        // and the file should not be there
        assert!(!file.try_exists().unwrap());

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        }
    }

    #[tokio::test]
    async fn test_rm_not_lazy() {
        let _s = span!(Level::INFO, "test_rm_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap6");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        // Create the directory
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        // Even though we're using not_lazy, let's ensure the test directory exists
        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");

        // We shouldn't need this for not_lazy, but let's be safe
        let (_, subfolder, _, _) = vm.0.get_paths(&mk).await.unwrap();
        if !subfolder.try_exists().unwrap_or(false) {
            fs::create_dir_all(&subfolder)
                .await
                .expect("Failed to create subfolder");
        }

        let _ = vm.put(&mk, &cid1).await.unwrap();

        // Get the paths to the subfolder and file created from the put
        let (_, subfolder, file, lazy_deleted_file) = vm.0.get_paths(&mk).await.unwrap();

        // Delete the block
        let cid2 = vm.rm(&mk).await.unwrap();
        assert_eq!(cid1, cid2);

        // This is not lazy so the lazy deleted file should not be there
        assert!(!lazy_deleted_file.try_exists().unwrap());
        // And the file should not be there either
        assert!(!file.try_exists().unwrap());
        // And since the subfolder is empty it should not be there either
        assert!(!subfolder.try_exists().unwrap());

        // Drop vm to ensure file handles are closed
        drop(vm);

        // Add a small delay
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Only try to remove if it exists
        if pb.try_exists().unwrap_or(false) {
            assert!(
                fs::remove_dir_all(&pb).await.is_ok(),
                "Failed to remove directory"
            );
        } else {
            println!("Directory was already removed as expected");
        }
    }

    #[tokio::test]
    async fn test_gc() {
        let _s = span!(Level::INFO, "test_gc").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap7");

        // Clean up and create directory
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }
        fs::create_dir_all(&pb)
            .await
            .expect("Failed to create test directory");

        // Create VM with default lazy deletion behavior
        let mut vm = Builder::new(&pb)
            .try_build()
            .await
            .expect("Failed to build VM");

        // Create keys and CIDs
        let mk1 = get_mk();
        let cid1 = get_cid(b"move every zig!");
        let mk2 = get_mk();
        let cid2 = get_cid(b"will come");

        // Ensure subdirectories exist before putting data
        let (_, subfolder1, _, _) = vm.0.get_paths(&mk1).await.unwrap();
        let (_, subfolder2, _, _) = vm.0.get_paths(&mk2).await.unwrap();
        fs::create_dir_all(&subfolder1)
            .await
            .expect("Failed to create subfolder1");
        fs::create_dir_all(&subfolder2)
            .await
            .expect("Failed to create subfolder2");

        // Add delay to ensure directories are created
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Put data
        vm.put(&mk1, &cid1).await.unwrap();
        vm.put(&mk2, &cid2).await.unwrap();

        // Verify data was stored correctly
        assert_eq!(vm.get(&mk1).await.unwrap(), cid1);
        assert_eq!(vm.get(&mk2).await.unwrap(), cid2);

        // Get paths for verification
        let (_, subfolder1, file1, lazy_deleted_file1) = vm.0.get_paths(&mk1).await.unwrap();
        let (_, subfolder2, file2, lazy_deleted_file2) = vm.0.get_paths(&mk2).await.unwrap();

        // Remove data
        vm.rm(&mk1).await.expect("Failed to remove mk1");
        vm.rm(&mk2).await.expect("Failed to remove mk2");

        // Since we're using lazy deletion (default), verify state
        assert!(lazy_deleted_file1.try_exists().unwrap_or(false));
        assert!(!file1.try_exists().unwrap_or(false));
        assert!(subfolder1.try_exists().unwrap_or(false));

        assert!(lazy_deleted_file2.try_exists().unwrap_or(false));
        assert!(!file2.try_exists().unwrap_or(false));
        assert!(subfolder2.try_exists().unwrap_or(false));

        // Run garbage collection
        vm.0.gc().await.expect("Failed to run garbage collection");

        // Verify garbage collection worked
        assert!(!lazy_deleted_file1.try_exists().unwrap_or(true));
        assert!(!file1.try_exists().unwrap_or(true));
        assert!(!subfolder1.try_exists().unwrap_or(true));

        assert!(!lazy_deleted_file2.try_exists().unwrap_or(true));
        assert!(!file2.try_exists().unwrap_or(true));
        assert!(!subfolder2.try_exists().unwrap_or(true));

        // Clean up
        drop(vm);
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }
    }
}
