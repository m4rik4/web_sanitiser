//! fetch delle eventuali sotto-risorse

use crate::error::SanitiserError;
use crate::input::network;
use crate::parser::{dom, sanitise_css, sanitise_html};
use crate::policy::{rules, SanitiserPolicy};
use crate::report::Action;
use std::collections::{HashSet, VecDeque};
use std::time::Instant;
use tokio::runtime::Handle;
use url::Url;

/// esegue un controllo delle sottorisorse a partire dall'HTML (già sanitizzato) della pagina, ritorna le azioni che descrivono cosa è stato scaricato/bloccato
pub fn crawl_subresources(
    base: &Url,
    root_html: &str,
    policy: &SanitiserPolicy,
    rt: &Handle,
    client: &reqwest::Client,
    started: Instant,
) -> Vec<Action> {
    let mut actions: Vec<Action> = Vec::new();

    let mut budget_bytes = policy.max_total_fetch_bytes;
    let mut budget_requests = policy.max_fetch_requests;
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    for link in absolute_links(base, root_html) {
        queue.push_back((link, 1));
    }

    while let Some((url, depth)) = queue.pop_front() {
        // il crawl è la fase più lunga quindi si controlla ad ogni giro prima della nuova connesione
        if policy.time_budget_exceeded(started) {
            // esaurito il budget di tempo per l'input
            break;
        }
        if depth > policy.max_fetch_depth {
            continue;
        }
        if budget_requests == 0 {
            actions.push(Action::new(
                "subresource-budget",
                "requests",
                "",
                "esaurito il numero massimo di richieste",
            ));
            break;
        }
        if !visited.insert(url.clone()) {
            continue; // già visitato
        }
        budget_requests -= 1;

        match rt.block_on(network::fetch(client, &url, policy)) {
            Ok((bytes, declared_mime)) => {
                if bytes.len() > budget_bytes {
                    actions.push(Action::new(
                        "subresource-budget",
                        url,
                        "",
                        "budget di byte totale superato",
                    ));
                    break;
                }
                budget_bytes = budget_bytes.saturating_sub(bytes.len());

                // sanitizzazione per tipo della sotto-risorsa
                let mime = declared_mime.clone().unwrap_or_default();
                let sniffed = rules::sniff_mime(&bytes);
                if rules::is_html(declared_mime.as_deref(), sniffed) {
                    let html = String::from_utf8_lossy(&bytes);
                    if let Ok((clean, mut sub_actions)) = sanitise_html(&html, policy) {
                        for a in &mut sub_actions {
                            a.location = format!("{url} :: {}", a.location); // ad ogni azione antepone l'url della posizione
                        }
                        actions.append(&mut sub_actions);
                        if depth < policy.max_fetch_depth {
                            if let Ok(b) = Url::parse(&url) {
                                for l in absolute_links(&b, &clean) {
                                    queue.push_back((l, depth + 1)); 
                                }
                            }
                        }
                    }
                    actions.push(Action::new("fetch-subresource", url, "html", "sanitizzata"));
                } else if policy.reject_active_types
                    && rules::is_declared_active_script(declared_mime.as_deref())
                {
                    // contenuto attivo, non riscrivibile in sicurezza
                    actions.push(Action::new(
                        "reject-active-subresource",
                        url,
                        mime,
                        "rifiutata: tipo attivo dichiarato (script)",
                    ));
                } else if rules::is_css(declared_mime.as_deref()) {
                    // CSS -> rimozione di javascript, expression e @import
                    let css = String::from_utf8_lossy(&bytes);
                    let (_clean, mut css_actions) = sanitise_css(&css);
                    for a in &mut css_actions {
                        a.location = format!("{url} :: {}", a.location);
                    }
                    actions.append(&mut css_actions);
                    actions.push(Action::new("fetch-subresource", url, "css", "sanitizzata"));
                } else if rules::image_too_large(&bytes, policy.max_image_pixels) {
                    actions.push(Action::new(
                        "reject-subresource",
                        url,
                        mime,
                        "rifiutata: immagine oltre il budget di pixel",
                    ));
                } else if rules::detect_xml_bomb(&bytes, policy.max_xml_entity_expansions) {
                    actions.push(Action::new(
                        "reject-subresource",
                        url,
                        mime,
                        "rifiutata: sospetto XML bomb",
                    ));
                } else if rules::pdf_has_active_content(&bytes) {
                    actions.push(Action::new(
                        "reject-subresource",
                        url,
                        mime,
                        "rifiutata: PDF con contenuto attivo",
                    ));
                } else {
                    // immagini e altri binari inerti: nessuna riscrittura, ma i controlli sui byte qui sopra sono già stati applicati
                    actions.push(Action::new("fetch-subresource", url, mime, "scaricata"));
                }
            }
            Err(e) => {
                let rule = if matches!(e, SanitiserError::SsrfBlocked(_)) {
                    "block-ssrf-subresource"
                } else {
                    "subresource-error"
                };
                actions.push(Action::new(rule, url, "", e.to_string()));
            }
        }
    }

    actions
}

// estrae i link e li risolve in URL assoluti http(s), scartando attributi inerti e i placeholder già neutralizzati
fn absolute_links(base: &Url, html: &str) -> Vec<String> {
    dom::extract_links(html)
        .into_iter()
        .filter_map(|l| {
            let lt = l.trim();
            let lower = lt.to_ascii_lowercase();
            if lt.is_empty()
                || lower.starts_with("javascript:")
                || lower.starts_with("data:")
                || lower.starts_with("mailto:")
                || lt.starts_with('#')
            {
                return None;
            }
            base.join(lt)
                .ok()
                .filter(|u| matches!(u.scheme(), "http" | "https")) // scheme() restituisce il protocollo dell'URL
                .map(|u| u.to_string())
        })
        .collect()
}
