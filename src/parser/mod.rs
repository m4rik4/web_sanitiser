//! strato di parsing/riscrittura HTML costruito sopra un parser sicuro esistente ('lol_html', rewriter in streaming)
pub mod rewriter;

pub use rewriter::sanitise_html;
