// SPDX-License-Identifier: FSL-1.1
use crate::Error;
use directories::ProjectDirs;
use log::debug;
use std::{fs, path::PathBuf};

/// initialie a local file in the correct configuration location by calculating
/// its correct location and then calling the init callback with the path so
/// the file can be created
pub fn initialize_local_file<'a, F>(
    path: Option<PathBuf>,
    org_dirs: &'a [&'a str; 3],
    default_filename: &'a str,
    init: F,
) -> Result<PathBuf, Error>
where
    F: FnOnce(PathBuf) -> Result<(), Error>,
{
    // get the path or look it up via ProjectDirs crate
    let path = {
        match path {
            Some(path) => path,
            None => {
                let pdirs = ProjectDirs::from(org_dirs[0], org_dirs[1], org_dirs[2])
                    .ok_or(Error::NoHome)?;
                let mut pb = pdirs.config_dir().to_path_buf();
                pb.push(default_filename);
                pb
            }
        }
    };

    // create the parent directories if needed
    let prefix = path.parent().ok_or(Error::NoHome)?;
    match prefix.try_exists() {
        Ok(result) => {
            if !result {
                debug!("creating: {}", prefix.display());
                fs::create_dir_all(prefix)?;
            }
        }
        Err(e) => return Err(Error::CannotInitializeConfig(format!("{}", e))),
    }

    // initialize the file using the callback if needed
    match path.try_exists() {
        Ok(result) => {
            if !result {
                init(path.clone())?
            }
        }
        Err(e) => return Err(Error::CannotInitializeConfig(format!("{}", e))),
    }

    Ok(path)
}
