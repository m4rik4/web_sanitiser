//! costruzione del Client

use crate::error::Result;
use crate::policy::rules::host_is_internal;
use crate::policy::SanitiserPolicy;
use std::net::IpAddr;
use std::time::Duration;

/// true se l'host è un riferimento di loopback (`localhost`, `127.0.0.0/8`, `::1`)
fn is_loopback_host(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    h.parse::<IpAddr>().map(|ip| ip.is_loopback()).unwrap_or(false)
}

/// politica di redirect in base alla configurazione delle policy
fn build_redirect_policy(policy: &SanitiserPolicy) -> reqwest::redirect::Policy {
    let max = policy.max_fetch_redirects;
    let block_private = policy.block_private_addresses;
    let allow_loopback = policy.allow_loopback;
    let allowlist = policy.fetch_host_allowlist.clone();

    reqwest::redirect::Policy::custom(move |attempt| { // il parametro attempt verra fornito da reqwest in occasione di redirect 
        if attempt.previous().len() >= max {
            return attempt.error(format!("troppi redirect (> {max})")); // interruzione del redirect, Reqwest convertirà questa decisione in un reqwest::Error, che verrà restituito dalla successiva client.get(...).send()
        }
        if block_private {
            // copiamo l'host in una String per non trattenere il borrow di attempt
            // quando poi lo consumiamo con .error() / .follow()
            let host = attempt.url().host_str().map(|h| h.to_string()); // map di option diverso da quello di da map di iterator, se è None non fa nulla
            if let Some(host) = host {
                let allowed = allowlist.iter().any(|h| h == &host); 
                if !allowed                                                 // se non è in allowlist 
                    && host_is_internal(host.as_str())                      // se è interno/privato 
                    && !(is_loopback_host(host.as_str()) && allow_loopback) // se non è un loopback esplicitamente autorizzato dalla policy
                {
                    return attempt
                        .error(format!("redirect verso host interno bloccato (SSRF): {host}"));
                }
            }
        }
        attempt.follow()
    })
}

/// costruisce il client HTTP una volta sola per l'intera esecuzione
/// reqwest::Client contiene il pool di connessioni e la configurazione TLS
/// progettato per essere condiviso con clone(): non duplica il pool quindi un solo client serve tutti i worker
pub fn build_client(policy: &SanitiserPolicy) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(Duration::from_millis(policy.fetch_timeout_ms))
        .redirect(build_redirect_policy(policy))
        .build()?)
}