//! riscrittura strutturale dell'HTML con 'lol_html'

use crate::error::{Result, SanitiserError};
use crate::policy::rules::{host_is_internal, host_is_punycode, url_has_host_confusion};
use crate::policy::{LinkAction, SanitiserPolicy};
use crate::report::Action;
use lol_html::{element, rewrite_str, RewriteStrSettings};
use std::cell::RefCell;
use std::rc::Rc;

/// potenziali problemi riscontrati sugli URL per memorizzarlo nell'azione tramite il valore originale dell'attributo
#[derive(Debug, PartialEq)]
enum UrlIssue {
    DangerousScheme,
    BlockedHost,
    InternalHost,
    Punycode,
    HostSplit,
}

/// analizza il valore di un attributo che porta un URL
fn analyse_url(val: &str, policy: &SanitiserPolicy) -> Option<UrlIssue> {
    let v = val.trim();
    let lower = v.to_ascii_lowercase();
    if lower.starts_with("javascript:") || lower.starts_with("vbscript:") {
        return Some(UrlIssue::DangerousScheme);
    }
    if lower.starts_with("data:") && !policy.allow_data_uri {
        return Some(UrlIssue::DangerousScheme);
    }
    if url_has_host_confusion(v) {
        return Some(UrlIssue::HostSplit);
    }
    if let Ok(u) = url::Url::parse(v) {
        if let Some(h) = u.host_str() {
            if policy.is_host_blocked(h) {
                return Some(UrlIssue::BlockedHost);
            }
            if host_is_internal(h) {
                return Some(UrlIssue::InternalHost);
            }
            if host_is_punycode(h) {
                return Some(UrlIssue::Punycode);
            }
        }
    }
    None
}

/// testo di sostituzione per un link neutralizzato secondo la policy
fn placeholder_for(issue: &UrlIssue) -> &'static str {
    match issue {
        UrlIssue::DangerousScheme => "#neutralised-scheme",
        UrlIssue::BlockedHost => "#blocked-host",
        UrlIssue::InternalHost => "#blocked-ssrf",
        UrlIssue::Punycode => "#flagged-idn",
        UrlIssue::HostSplit => "#flagged-host-split",
    }
}

fn rule_name(issue: &UrlIssue) -> &'static str {
    match issue {
        UrlIssue::DangerousScheme => "neutralise-uri-scheme",
        UrlIssue::BlockedHost => "block-listed-host",
        UrlIssue::InternalHost => "block-ssrf-reference",
        UrlIssue::Punycode => "flag-idn-homograph",
        UrlIssue::HostSplit => "flag-host-split",
    }
}

/// sanitizza un documento HTML -> restituisce il documento pulito e la lista di azioni.
pub fn sanitise_html(html: &str, policy: &SanitiserPolicy) -> Result<(String, Vec<Action>)> {
    let actions: Rc<RefCell<Vec<Action>>> = Rc::new(RefCell::new(Vec::new())); //fuori closure
    let acc = actions.clone(); //dentro closure

    let output = rewrite_str(
        html,
        RewriteStrSettings {
            // campo della struct per selettori + funzioni da applicare -> utilizziamo una sola macro element! di lol_html (e quindi una sola funzione) per tutti i tipi di selettori *
            element_content_handlers: vec![element!("*", move |el| {    // el elemento incontrato con selettore * (ogni elemento)
                let tag = el.tag_name();

                // rimozione di qualunque attributo che inizia con 'on'
                let handler_attrs: Vec<String> = el
                    .attributes()
                    .iter()
                    .map(|a| a.name())
                    .filter(|n| n.starts_with("on"))
                    .collect();
                for name in handler_attrs {
                    el.remove_attribute(&name);
                    acc.borrow_mut().push(Action::new(
                        "strip-inline-handler",
                        format!("<{tag}> @{name}"),
                        name,
                        "",
                    ));
                }

                // rimozione di elementi strutturalmente attivi
                match tag.as_str() {
                    // codice javascript
                    "script" => {
                        let src = el.get_attribute("src");
                        if !policy.script_src_allowed(src.as_deref()) {
                            acc.borrow_mut().push(Action::new(
                                "remove-script",
                                "<{tag}>",
                                src.unwrap_or_else(|| "inline".into()),
                                "",
                            ));
                            el.remove();
                        }
                        return Ok(());
                    }
                    // contenuto attivo incorporato
                    "iframe" | "object" | "embed" | "frame" => {
                        let target = el.get_attribute("src").or_else(|| el.get_attribute("data"));
                        let allowed = target
                            .as_deref()
                            .map(|t| policy.embed_src_allowed(t))
                            .unwrap_or(false);
                        if !allowed {
                            let (rule, original) =
                                match target.as_deref().and_then(|t| analyse_url(t, policy)) { 
                                    Some(issue) => {
                                        (rule_name(&issue), target.unwrap_or_default())
                                    }
                                    None => (
                                        "remove-active-embed",
                                        target.unwrap_or_else(|| "inline".into()),
                                    ),
                                };
                            acc.borrow_mut().push(Action::new(
                                rule,
                                format!("<{tag}>"),
                                original,
                                "",
                            ));
                            el.remove();
                        }
                        return Ok(());
                    }
                    // metadati che possono causare redirect automatico tramite il refresh
                    "meta" => {
                        let http_equiv = el.get_attribute("http-equiv").unwrap_or_default();
                        if http_equiv.eq_ignore_ascii_case("refresh") {
                            acc.borrow_mut().push(Action::new(
                                "remove-meta-refresh",
                                "<meta http-equiv=refresh>",
                                el.get_attribute("content").unwrap_or_default(),
                                "",
                            ));
                            el.remove();
                        }
                        return Ok(());
                    }
                    _ => {}
                }

                // attributi che portano URL su elementi generici (a, img, form, ...)
                for attr in ["href", "src", "action", "data", "poster", "formaction"] {
                    if let Some(val) = el.get_attribute(attr) {
                        if let Some(issue) = analyse_url(&val, policy) {
                            let replacement = match policy.link_action {
                                LinkAction::Remove => {
                                    el.remove_attribute(attr);
                                    String::new()
                                }
                                LinkAction::Placeholder => {
                                    let ph = placeholder_for(&issue).to_string();
                                    el.set_attribute(attr, &ph)?;
                                    ph
                                }
                                LinkAction::Rewrite => {
                                    // conserva l'URL originale rendendolo inerte (comincia con #)
                                    let rw = format!("{}:{}", placeholder_for(&issue), val);
                                    el.set_attribute(attr, &rw)?;
                                    rw
                                }
                            };
                            acc.borrow_mut().push(Action::new(
                                rule_name(&issue),
                                format!("<{tag}> @{attr}"),
                                val,
                                replacement,
                            ));
                        }
                    }
                }

                Ok(())
            })],
            ..RewriteStrSettings::default() // per tutti gli altri campi, usa i valori di default
        },
    )
    .map_err(|e| SanitiserError::Parse(e.to_string()))?; //conversione manuale dell'errore

    let acts = Rc::try_unwrap(actions)
        .map(|c| c.into_inner())
        .unwrap_or_else(|rc| rc.borrow().clone()); // recupera il Vec direttamente se Rc è l'unico proprietario, altrimenti lo clona
    Ok((output, acts))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitise_html_removes_dangerous_url() {
        let html = r#"<a href="javascript:alert(1)">link</a>"#;
        let policy = SanitiserPolicy::default();

        let (clean, actions) = sanitise_html(html, &policy).unwrap();

        assert!(!clean.contains("javascript:"));
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].rule, "neutralise-uri-scheme");
    }
}