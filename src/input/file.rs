//! lettura dal file system e ricerca ricorsiva nella directory

use std::path::{Path, PathBuf};
use crate::error::Result;

/// espande ricorsivamente una directory riempiendo una lista dei file contenuti
pub fn expand_dir(root: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?; // entry potrebbe non esserci
            let file_type = entry.file_type()?; // ignora collegamenti, perché tratta solo directory o file
            let path = entry.path();
            if file_type.is_dir() {
                stack.push(path);
            } else if file_type.is_file() {
                out.push(path);
            }
        }
    }
    Ok(out)
}
