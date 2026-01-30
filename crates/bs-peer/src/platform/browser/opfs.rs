//! Origin Privacy File System (OPFS) blockstore implementation.
//!
//! There are two types: [`OPFSBlockstore`] which is the actual blockstore implementation
//! and [`OPFSWrapped`] which wraps it in a `SendWrapper` to make it [std::marker::Send].
use super::Error;
use wasm_bindgen::JsValue;
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    window, Blob, FileSystemDirectoryHandle, FileSystemFileHandle, FileSystemGetFileOptions,
    FileSystemWritableFileStream,
};

use blockstore::Blockstore;
use send_wrapper::SendWrapper;
use std::ops::Deref;

/// Uses Origin Privacy File System (OPFS) to store blocks
#[derive(Debug, Clone)]
pub struct OPFSBlockstore {
    inner: FileSystemDirectoryHandle,
}

impl OPFSBlockstore {
    /// Create a new OPFSBlockstore
    pub async fn new() -> Result<Self, JsValue> {
        let window = window().ok_or_else(|| JsValue::from_str("No window available"))?;
        let navigator = window.navigator();
        let storage = navigator.storage();

        let directory_handle: FileSystemDirectoryHandle =
            JsFuture::from(storage.get_directory()).await?.into();

        Ok(Self {
            inner: directory_handle,
        })
    }

    /// Put block bytes into the OPFS under the given name
    pub async fn put_opfs(&self, name: &str, data: Vec<u8>) -> Result<(), JsValue> {
        let options = FileSystemGetFileOptions::new();
        options.set_create(true);

        let file_handle: FileSystemFileHandle =
            JsFuture::from(self.inner.get_file_handle_with_options(name, &options))
                .await?
                .into();

        let writable: FileSystemWritableFileStream =
            JsFuture::from(file_handle.create_writable()).await?.into();

        JsFuture::from(writable.write_with_u8_array(&data)?).await?;

        JsFuture::from(writable.close()).await?;

        Ok(())
    }

    /// Get block bytes from the OPFS by name
    pub async fn get_opfs(&self, name: &str) -> Result<Vec<u8>, JsValue> {
        let file_handle_result = JsFuture::from(self.inner.get_file_handle(name)).await;

        match file_handle_result {
            Ok(handle) => {
                let file_handle: FileSystemFileHandle = handle.into();

                let file: Blob = JsFuture::from(file_handle.get_file()).await?.into();
                let array_bufer = JsFuture::from(file.array_buffer()).await?;
                let u8_array = js_sys::Uint8Array::new(&array_bufer);

                Ok(u8_array.to_vec())
            }
            Err(_) => Err(JsValue::from_str("File not found")),
        }
    }
}

impl Blockstore for OPFSBlockstore {
    async fn get<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
    ) -> blockstore::Result<Option<Vec<u8>>> {
        match self.get_opfs(&cid.to_string()).await {
            Ok(data) => Ok(Some(data)),
            Err(_) => Ok(None),
        }
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        self.put_opfs(&cid.to_string(), data.to_vec())
            .await
            .map_err(|_| blockstore::Error::StoredDataError("Failed to put data".to_string()))?;

        Ok(())
    }

    async fn remove<const S: usize>(&self, _cid: &cid::CidGeneric<S>) -> blockstore::Result<()> {
        Ok(())
    }

    async fn close(self) -> blockstore::Result<()> {
        Ok(())
    }
}

/// A Wrapper sturct around OPFSBlockstore so that we can make it [Send]
#[derive(Debug, Clone)]
pub struct OPFSWrapped {
    inner: SendWrapper<OPFSBlockstore>,
}

impl OPFSWrapped {
    /// Create a new OPFSWrapped blockstore
    // Takes a noop string parameter to match the native blockstore interface
    pub async fn new(_noop: String) -> Result<Self, Error> {
        let handler = OPFSBlockstore::new()
            .await
            .map_err(|e| Error::OPFSBlockstore(e.as_string().unwrap_or_default()))?;
        Ok(Self {
            inner: SendWrapper::new(handler),
        })
    }
}

impl Blockstore for OPFSWrapped {
    async fn get<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
    ) -> blockstore::Result<Option<Vec<u8>>> {
        tracing::debug!("Getting block from OPFS for CID: {:?}", cid);
        self.inner.deref().get(cid).await
    }

    async fn put_keyed<const S: usize>(
        &self,
        cid: &cid::CidGeneric<S>,
        data: &[u8],
    ) -> blockstore::Result<()> {
        self.inner.deref().put_keyed(cid, data).await
    }

    async fn remove<const S: usize>(&self, _cid: &cid::CidGeneric<S>) -> blockstore::Result<()> {
        //todo!();
        Ok(())
    }

    async fn close(self) -> blockstore::Result<()> {
        Ok(())
    }
}
