//! lettura dal file system e ricerca ricorsiva nella directory

use std::path::{Path, PathBuf};
use crate::error::{Result, SanitiserError};

/// legge un file, ricavando il MIME dichiarato dall'estensione (non affidabile)
// dimensione verificata sui metadati per non allocare il contenuto
pub fn read_file(path: &Path, max_bytes: usize) -> Result<(Vec<u8>, Option<String>)> {
    let dimensione = std::fs::metadata(path)?.len();
    if dimensione > max_bytes as u64 {
        return Err(SanitiserError::BudgetExceeded(format!(
            "{}: {dimensione} byte, oltre max_input_bytes ({max_bytes})",
            path.display()
        )));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_decides_the_declared_mime() {
        for (name, expected) in [
            ("a.html", Some("text/html")),
            ("a.HTM", Some("text/html")),  // maiuscole comprese
            ("a.JPG", Some("image/jpeg")),
            ("a.css", Some("text/css")),
            ("a.tar.gz", None),            // conta solo l'ultima estensione
            ("LEGGIMI", None),             // nessuna estensione
        ] {
            assert_eq!(mime_from_extension(Path::new(name)).as_deref(), expected, "{name}");
        }
    }

    #[test]
    fn read_file_reads_the_bytes_and_declares_from_the_name() {
        let (bytes, declared) = read_file(Path::new("corpus/benign/simple.html"), 10 * 1024 * 1024).unwrap();
        assert!(!bytes.is_empty());
        assert_eq!(declared.as_deref(), Some("text/html"));
    }

    #[test]
    fn descends_into_subdirectories() {
        let files = expand_dir(Path::new("corpus")).unwrap();
        assert!(files.iter().all(|p| p.is_file()));           // mai le directory
        assert!(files.iter().any(|p| p.ends_with("benign/simple.html")));
        assert!(files.iter().any(|p| p.ends_with("malicious/ssrf-internal.html")));
    }

    #[test]
    fn a_missing_directory_is_an_error() {
        assert!(expand_dir(Path::new("corpus/non-esiste")).is_err());
    }
}