//! strato di parsing/riscrittura HTML costruito sopra un parser sicuro esistente ('lol_html', rewriter in streaming)
pub mod rewriter;
pub mod dom;
pub mod css;

pub use rewriter::sanitise_html;
pub use css::sanitise_css;