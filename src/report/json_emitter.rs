//! scrittura del report in json, il formato leggibile da altri programmi
//! richiesto dalla traccia (sez. 3)

use crate::error::Result;
use crate::report::Report;
use std::path::Path;

/// report come stringa json indentata, pronta da stampare
pub fn to_json_string(report: &Report) -> Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// stessa cosa, ma scritta su file
pub fn write_to_file(report: &Report, path: &Path) -> Result<()> {
    let json = to_json_string(report)?;
    std::fs::write(path, json)?;
    Ok(())
}
