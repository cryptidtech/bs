// SPDX-License-Identifier: Apache-2.0
use crate::cidmap::{self, CidMap};
use multicid::EncodedVlad;

/// The VladMap type that maps Vlad to Cid
pub type VladMap = CidMap<EncodedVlad>;
/// The VladMap builder
pub type Builder = cidmap::Builder<EncodedVlad>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cids::Cids;
    use multicid::{cid, vlad, Cid, EncodedVlad, Vlad};
    use multicodec::Codec;
    use multihash::mh;
    use multikey::{mk, Multikey, Views as _};
    use multiutil::EncodingInfo;
    use rng::StdRng;
    use std::path::PathBuf;
    use tokio::{fs, test};
    use tracing::{span, Level};

    // returns a random Ed25519 secret key as a Multikey
    fn get_mk() -> Multikey {
        let mut rng = StdRng::from_os_rng();
        mk::Builder::new_from_random_bytes(Codec::Ed25519Priv, &mut rng)
            .unwrap()
            .try_build()
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

    // returns a signed vlad
    fn get_vlad(b: &[u8]) -> EncodedVlad {
        let mk = get_mk();
        let cid = get_cid(b);

        vlad::Builder::default()
            .with_signing_key(&mk)
            .with_cid(&cid)
            .try_build_encoded(|cid| {
                let signing_view = mk.sign_view()?;
                let cidv: Vec<u8> = cid.clone().into();
                let ms = signing_view.sign(&cidv, false, None)?;
                let msv: Vec<u8> = ms.clone().into();
                Ok(msv)
            })
            .unwrap()
    }

    #[test]
    async fn test_builder_lazy() {
        let _s = span!(Level::INFO, "test_builder_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap1");

        let vm = Builder::new(&pb).try_build().await.unwrap();
        assert_eq!(vm.0.root, pb);
        assert!(vm.0.lazy);
        assert_eq!(vm.0.base_encoding, Vlad::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_builder_not_lazy() {
        let _s = span!(Level::INFO, "test_builder_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap2");

        let vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();
        assert_eq!(vm.0.root, pb);
        assert!(!vm.0.lazy);
        assert_eq!(vm.0.base_encoding, Vlad::preferred_encoding());
        assert!(pb.try_exists().is_ok());
        assert!(pb.is_dir());

        let mut dir = fs::read_dir(&pb).await.unwrap();
        while let Some(d) = dir.next_entry().await.unwrap() {
            assert!(d.file_type().await.unwrap().is_dir());
        }

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_put_lazy() {
        let _s = span!(Level::INFO, "test_put_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap3");

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let vlad = get_vlad(b"for great justice!");
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&vlad, &cid1).await.unwrap();
        let cid2 = vm.get(&vlad).await.unwrap();

        assert_eq!(cid1, cid2);
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_put_not_lazy() {
        let _s = span!(Level::INFO, "test_put_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap4");

        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let vlad = get_vlad(b"for great justice!");
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&vlad, &cid1).await.unwrap();
        let cid2 = vm.get(&vlad).await.unwrap();

        assert_eq!(cid1, cid2);
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_lazy() {
        let _s = span!(Level::INFO, "test_rm_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap5");

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let vlad = get_vlad(b"for great justice!");
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&vlad, &cid1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, _, file, lazy_deleted_file) = vm.0.get_paths(&vlad).await.unwrap();

        // lazy delete the block
        let cid2 = vm.rm(&vlad).await.unwrap();
        assert_eq!(cid1, cid2);

        // this is lazy so the lazy deleted file should sill be there
        assert!(lazy_deleted_file.try_exists().unwrap());
        // and the file should not be there
        assert!(!file.try_exists().unwrap());
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_not_lazy() {
        let _s = span!(Level::INFO, "test_rm_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap6");

        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let vlad = get_vlad(b"for great justice!");
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&vlad, &cid1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, subfolder, file, lazy_deleted_file) = vm.0.get_paths(&vlad).await.unwrap();

        // delete the block
        let cid2 = vm.rm(&vlad).await.unwrap();
        assert_eq!(cid1, cid2);

        // this is not lazy so the lazy deleted file should not be there
        assert!(!lazy_deleted_file.try_exists().unwrap());
        // and the file should not be there either
        assert!(!file.try_exists().unwrap());
        // and since the subfolder is empty it should not be there either
        assert!(!subfolder.try_exists().unwrap());
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_gc() {
        let _s = span!(Level::INFO, "test_gc").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap7");

        // Make sure directory doesn't exist from prior test run
        if pb.try_exists().unwrap_or(false) {
            let _ = fs::remove_dir_all(&pb).await;
        }

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let vlad1 = get_vlad(b"for great justice!");
        let cid1 = get_cid(b"move every zig!");

        // Add debugging to see if the put succeeds
        vm.put(&vlad1, &cid1).await.unwrap();

        // Verify the put worked
        assert_eq!(vm.get(&vlad1).await.unwrap(), cid1);

        let vlad2 = get_vlad(b"someday");
        let cid2 = get_cid(b"will come");
        vm.put(&vlad2, &cid2).await.unwrap();

        // Verify the put worked
        assert_eq!(vm.get(&vlad2).await.unwrap(), cid2);

        // Remove with better error handling
        vm.rm(&vlad1).await.unwrap();
        vm.rm(&vlad2).await.unwrap();

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder1, file1, lazy_deleted_file1) = vm.0.get_paths(&vlad1).await.unwrap();
        assert!(lazy_deleted_file1.try_exists().unwrap());
        assert!(!file1.try_exists().unwrap());
        assert!(subfolder1.try_exists().unwrap());

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder2, file2, lazy_deleted_file2) = vm.0.get_paths(&vlad2).await.unwrap();
        assert!(lazy_deleted_file2.try_exists().unwrap());
        assert!(!file2.try_exists().unwrap());
        assert!(subfolder2.try_exists().unwrap());

        // garbage collect
        vm.0.gc().await.unwrap();

        // no files nor folders should exist
        assert!(!lazy_deleted_file1.try_exists().unwrap());
        assert!(!file1.try_exists().unwrap());
        assert!(!subfolder1.try_exists().unwrap());
        assert!(!lazy_deleted_file2.try_exists().unwrap());
        assert!(!file2.try_exists().unwrap());
        assert!(!subfolder2.try_exists().unwrap());

        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }
}
