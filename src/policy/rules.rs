//! regole di ispezione

use std::net::{IpAddr, Ipv4Addr};

/// true se un host testuale fa riferimento a una destinazione interna o privata
///
/// copre anche le codifiche IPv4 alternative: Un host può essere scritto 
/// in forme che i risolutori accettano ma che un confronto testuale ingenuo 
/// non riconosce: oltre alla forma canonica (127.0.0.1), l'intero decimale 
/// singolo (2130706433) e l'esadecimale (0x7f000001) denotano lo stesso indirizzo
pub fn host_is_internal(host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase(); //URL IPv6 solitamente scritti così: http://[::1]:8080 dove l'host è [[::1]]
    if h == "localhost" || h.ends_with(".localhost") || h == "0.0.0.0" {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip_is_internal(&ip);
    }
    if let Some(v4) = decode_ipv4_alternate(&h) {
        return ip_is_internal(&IpAddr::V4(v4)); //v4 è Ipv4Addr ma ip_is_internal richiede come parametro un IpAddr -> lo riconduco alla sua struttura
    }
    false
}

/// decodifica un host in una delle codifiche IPv4 "non canoniche"
fn decode_ipv4_alternate(h: &str) -> Option<Ipv4Addr> {
    let as_u32 = if let Some(hex) = h.strip_prefix("0x") {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) { //condizione di uscita anticipata
            return None;
        }
        u32::from_str_radix(hex, 16).ok() //conversione in hex
    } else if !h.is_empty() && h.chars().all(|c| c.is_ascii_digit()) {
        h.parse::<u32>().ok()
    } else {
        None
    };
    as_u32.map(Ipv4Addr::from)
}

/// classifica un IP come interno/privato/non instradabile pubblicamente
pub fn ip_is_internal(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xFE00) == 0xFC00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xFFC0) == 0xFE80
        }
    }
}
