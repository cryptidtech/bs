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

    #[test]
    async fn test_builder_lazy() {
        let _s = span!(Level::INFO, "test_builder_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap1");

        let vm = Builder::new(&pb).try_build().await.unwrap();
        assert_eq!(vm.0.root, pb);
        assert!(vm.0.lazy);
        assert_eq!(vm.0.base_encoding, Multikey::preferred_encoding());
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
        assert_eq!(vm.0.base_encoding, Multikey::preferred_encoding());
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

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&mk, &cid1).await.unwrap();
        let cid2 = vm.get(&mk).await.unwrap();

        assert_eq!(cid1, cid2);
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_put_not_lazy() {
        let _s = span!(Level::INFO, "test_put_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap4");

        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&mk, &cid1).await.unwrap();
        let cid2 = vm.get(&mk).await.unwrap();

        assert_eq!(cid1, cid2);
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_lazy() {
        let _s = span!(Level::INFO, "test_rm_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap5");

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");
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
        assert!(fs::remove_dir_all(&pb).await.is_ok());
    }

    #[test]
    async fn test_rm_not_lazy() {
        let _s = span!(Level::INFO, "test_rm_not_lazy").entered();
        let mut pb = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        pb.push(".fsvladmap6");

        let mut vm = Builder::new(&pb).not_lazy().try_build().await.unwrap();

        let mk = get_mk();
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&mk, &cid1).await.unwrap();

        // get the paths to the subfolder and file created from the put
        let (_, subfolder, file, lazy_deleted_file) = vm.0.get_paths(&mk).await.unwrap();

        // delete the block
        let cid2 = vm.rm(&mk).await.unwrap();
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

        let mut vm = Builder::new(&pb).try_build().await.unwrap();

        let mk1 = get_mk();
        let cid1 = get_cid(b"move every zig!");
        let _ = vm.put(&mk1, &cid1).await.unwrap();
        let mk2 = get_mk();
        let cid2 = get_cid(b"will come");
        let _ = vm.put(&mk2, &cid2).await.unwrap();

        let _ = vm.rm(&mk1).await.unwrap();
        let _ = vm.rm(&mk2).await.unwrap();

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder1, file1, lazy_deleted_file1) = vm.0.get_paths(&mk1).await.unwrap();
        assert!(lazy_deleted_file1.try_exists().unwrap());
        assert!(!file1.try_exists().unwrap());
        assert!(subfolder1.try_exists().unwrap());

        // lazy delete, check that the file is gone, the lazy delete file and folder still exist
        let (_, subfolder2, file2, lazy_deleted_file2) = vm.0.get_paths(&mk2).await.unwrap();
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
