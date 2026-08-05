//! costruzione del Client

use crate::input::Loaded;
use crate::error::{Result, SanitiserError};
use crate::policy::rules::{host_is_internal, ip_is_internal};
use crate::policy::SanitiserPolicy;
use std::net::{IpAddr, ToSocketAddrs};
use std::time::Duration;
use url::Url;

/// guard SSRF: risolve l'host e rifiuta destinazioni interne/private, salvo host
/// esplicitamente in allow-list o loopback consentito
pub fn ssrf_guard(parsed: &Url, policy: &SanitiserPolicy) -> Result<()> {
    let host = parsed
        .host_str()
        .ok_or_else(|| SanitiserError::InvalidUrl(parsed.to_string()))?;

    if policy.fetch_host_allowlist.iter().any(|h| h == host) {
        return Ok(());
    }
    if !policy.block_private_addresses {
        return Ok(());
    }

    let port = parsed.port_or_known_default().unwrap_or(80);
    let addrs = (host, port)
        .to_socket_addrs()  // da tupla a SocketAddr, funzione potrebbe bloccare il thread -> restituisce un vettore perchè un hostname può corrispondere a più indirizzi di rete possibili
        .map_err(|e| SanitiserError::Fetch(format!("risoluzione DNS di {host}: {e}")))?;

    for addr in addrs {
        let ip = addr.ip();
        if ip_is_internal(&ip) && !(ip.is_loopback() && policy.allow_loopback) {
            return Err(SanitiserError::SsrfBlocked(format!("{host} -> {ip}")));
        }
    }
    Ok(())
}

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

/// scarica un URL applicando timeout e tetto sui byte 
/// il corpo è letto a chunk e il tetto limita gli output
/// la difesa contro compression/response bomb.
pub async fn fetch(
    client: &reqwest::Client,
    url: &str,
    policy: &SanitiserPolicy,
) -> Result<Loaded> {
    let parsed = Url::parse(url)?;
    ssrf_guard(&parsed, policy)?;

    // reqwest rimuove gli header di encoding gestiti automaticamente (gzip)
    let mut resp = client.get(parsed).send().await?; //chiamata non bloccante -> se la rete impiega tempo per rispondere gli altri thread tokio continuano ad eseguire altre fetch di rete

    // con la feature gzip reqwest decomprime il corpo in streaming e rimuove l'header Content-Encoding
    if policy.reject_content_encoding {
        if let Some(enc) = resp.headers().get(reqwest::header::CONTENT_ENCODING) { // verifica se è rimasto un Content-Encoding non gestito dopo la decompressione automatica di reqwest
            let e = enc.to_str().unwrap_or("").trim().to_ascii_lowercase();
            if !e.is_empty() && e != "identity" { // identity valore standard http per nessuna codifica applicata
                return Err(SanitiserError::Refused(format!(
                    "codifica non supportata (Content-Encoding: {e}): contenuto non ispezionabile"
                )));
            }
        }
    }

    let declared_mime = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok()) // and_then evita un Option<Option<&str>>
        .map(|s| s.to_string()); 
    
    let mut bytes: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? { // inizia a decomprimere e controllare il body - chiamata non bloccante
        if bytes.len() + chunk.len() > policy.max_input_bytes {
            return Err(SanitiserError::BudgetExceeded(format!(
                "risposta oltre {} byte da {url}",
                policy.max_input_bytes
            )));
        }
        bytes.extend_from_slice(&chunk);  
    }

    Ok(Loaded {
        origin: url.to_string(),
        kind: "url",
        bytes,
        declared_mime,
    })
}