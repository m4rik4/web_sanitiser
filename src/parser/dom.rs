//! estrazione degli URL referenziati

use lol_html::{element, rewrite_str, RewriteStrSettings};
use std::cell::RefCell;
use std::rc::Rc;

/// estrae tutti gli URL referenziati da un documento HTML, non modificando il documento
pub fn extract_links(html: &str) -> Vec<String> {
    let links: Rc<RefCell<Vec<String>>> = Rc::new(RefCell::new(Vec::new())); //fuori closure
    let acc = links.clone(); //dentro closure
    let _ = rewrite_str(
        html,
        RewriteStrSettings {
            element_content_handlers: vec![element!("*", move |el| {
                for attr in ["href", "src", "action", "data", "poster", "formaction"] {
                    if let Some(v) = el.get_attribute(attr) {
                        acc.borrow_mut().push(v);
                    }
                }
                Ok(())
            })],
            ..RewriteStrSettings::default()
        },
    );
    Rc::try_unwrap(links)
        .map(|c| c.into_inner())
        .unwrap_or_else(|rc| rc.borrow().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_extraction() {
        let html = r#"
            <a href="https://example.com">link</a>
            <img src="/image.png">
            <form action="/submit">
            <div data="/data"></div>
            <video poster="/poster.jpg"></video>
        "#;

        let links = extract_links(html);

        assert_eq!(
            links,
            vec![
                "https://example.com",
                "/image.png",
                "/submit",
                "/data",
                "/poster.jpg",
            ]
        );
    }
}