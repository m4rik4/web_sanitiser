//! lettura dal file system e ricerca ricorsiva nella directory

use std::path::{Path, PathBuf};
use crate::error::Result;

/// legge un file, ricavando il MIME dichiarato dall'estensione (non affidabile)
pub fn read_file(path: &Path) -> Result<(Vec<u8>, Option<String>)> {
    let bytes = std::fs::read(path)?;
    Ok((bytes, mime_from_extension(path)))
}

/// MIME "dichiarato" dedotto dall'estensione. È solo un suggerimento e necessita di controlli ulteriori
pub fn mime_from_extension(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase(); // extension ritorna OsStr, to_str converte in &str, to_ascii_lowercase ritorna String in minuscolo
    let m = match ext.as_str() { // as_str perché poi il match lo fa con dei literal di stringa
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "pdf" => "application/pdf",
        "xml" => "application/xml",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        _ => return None,
    };
    Some(m.to_string())
}

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
