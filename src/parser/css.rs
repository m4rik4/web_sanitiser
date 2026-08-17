//! sanitizzazione dei fogli di stile CSS

use crate::report::Action;

/// sanitizza un CSS, ritornando il testo ripulito e la lista di azioni applicate
pub fn sanitise_css(css: &str) -> (String, Vec<Action>) {
    let mut actions = Vec::new();
    let mut out = css.to_string();

    if contains_ci(&out, "javascript:") {
        out = replace_ci(&out, "javascript:", "removed:");
        actions.push(Action::new(
            "neutralise-css-url",
            "css url()",
            "javascript:",
            "removed:",
        ));
    }
    if contains_ci(&out, "expression(") {
        out = replace_ci(&out, "expression(", "void(");
        actions.push(Action::new(
            "remove-css-expression",
            "css expression()",
            "expression(",
            "void(",
        ));
    }
    if contains_ci(&out, "@import") {
        out = strip_import(&out);
        actions.push(Action::new("remove-css-import", "css @import", "@import", ""));
    }

    (out, actions)
}

/// confronto case-insensitive di contenimento
fn contains_ci(hay: &str, needle: &str) -> bool {
    let h = hay.to_ascii_lowercase();
    let n = needle.to_ascii_lowercase();
    h.contains(n.as_str())
}

/// sostituzione case-insensitive di tutte le occorrenze (Rust non ha un replace_ignore_ascii_case())
fn replace_ci(hay: &str, needle: &str, repl: &str) -> String {
    let lower_hay = hay.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    if lower_needle.is_empty() {
        return hay.to_string();
    }
    let mut result = String::with_capacity(hay.len());
    let mut i = 0;
    //rimpiazzo manuale di needle con repl
    while i < hay.len() {
        if lower_hay[i..].starts_with(lower_needle.as_str()) {
            result.push_str(repl);
            i += needle.len(); 
        } else {
            let ch = hay[i..].chars().next().unwrap();
            result.push(ch);
            i += ch.len_utf8(); //non fa semplicemente i += 1 perché in UTF-8 un carattere può occupare più di un byte
        }
    }
    result
}

/// rimuove ogni dichiarazione '@import ...;' (fino al primo ';' incluso)
fn strip_import(css: &str) -> String {
    let lower = css.to_ascii_lowercase();
    let mut out = String::with_capacity(css.len());
    let mut i = 0;
    while i < css.len() {
        if lower[i..].starts_with("@import") {
            match css[i..].find(';') {
                Some(semi) => i += semi + 1,
                None => i = css.len(),
            }
        } else {
            let ch = css[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}
