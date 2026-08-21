//! scrittura del report in json, il formato leggibile da altri programmi
//! richiesto dalla traccia (sez. 3)

use crate::error::Result;
use crate::report::Report;
use std::path::Path;

/// report come stringa json indentata, pronta da stampare
pub fn to_json_string(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// scrive il report json su file, creando le directory che mancano
pub fn write_to_file(report: &Report, path: &Path) -> Result<()> {
    let json = to_json_string(report)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?; // se il percorso è solo un nome di file, `parent()` dà un percorso vuoto e la chiamata non fa niente
    }
    std::fs::write(path, json)?;
    Ok(())
}
