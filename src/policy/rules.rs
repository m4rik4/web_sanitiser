//! regole di ispezione

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

/// true se un host testuale fa riferimento a una destinazione interna o privata
///
/// copre anche le codifiche IPv4 alternative: un host può essere scritto in forme che i risolutori accettano ma che un confronto testuale ingenuo 
/// non riconosce: oltre alla forma canonica (127.0.0.1), l'intero decimale singolo (2130706433) e l'esadecimale (0x7f000001) denotano lo stesso indirizzo
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

/// `true` se il MIME dichiarato è un tipo di script eseguibile, questi tipi vanno rifiutati come contenuto attivo a prescindere
pub fn is_declared_active_script(declared: Option<&str>) -> bool { // ad esempio text/html; charset=UTF-8
    let declare = declared.map(|d| d.split(';').next().unwrap_or("").trim().to_ascii_lowercase()); // normalizza un MIME dichiarato al solo tipo base (senza parametri, minuscolo)
    match declare {
        Some(d) => {
            d.ends_with("/javascript")
                || d.ends_with("/ecmascript")
                || d == "application/x-javascript"
        }
        None => false,
    }
}

/// numero massimo di livelli di  annidamento fra entità che accettiamo di seguire
const MAX_ENTITY_DEPTH: usize = 128;  // hardcoded e non policy configurabile perchè legato alla profondità dello stack di chiamata stackoverflow -> abort del processo intero (crash su input non fidato)

/// rilevamento XML bomb ("Billion Laughs") che controlla se una qualsiasi entità potrebbe espandersi in un numero di token >= `max_expansions`
pub fn detect_xml_bomb(bytes: &[u8], max_expansions: usize) -> bool {
    let text = String::from_utf8_lossy(bytes);
    let entities = parse_entities(&text);
    if entities.is_empty() {
        return false;
    }
    let cap = max_expansions.max(1) as u64; //u64 per rappresentare potenzialmente l'espansione intermedia di una bomba profonda
    let mut memo: HashMap<String, u64> = HashMap::new();
    entities
        .keys()
        .any(|name| expansion_count(name, &entities, &mut memo, cap, 0) >= cap)
}

/// estrae le definizioni di entità `<!ENTITY nome "valore">` dal testo
fn parse_entities(text: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let lower = text.to_ascii_lowercase();
    let mut idx = 0;
    while idx < lower.len() {
        let Some(pos) = lower[idx..].find("<!entity") else { break };
        let start = idx + pos + "<!entity".len();
        // dichiarazione troncata a fine input
        if start >= text.len() {
            break;
        }
        
        // cerca il carattere '>' solo fuori dalle stringhe quotate per evitare falsi tagli
        let mut end = text.len();
        let mut quote: Option<char> = None;

        for (offset, c) in text[start..].char_indices() {
            match c {
                '"' | '\'' => {
                    if quote == Some(c) {
                        quote = None;
                    } else if quote.is_none() {
                        quote = Some(c);
                    }
                }
                '>' if quote.is_none() => {
                    end = start + offset;
                    break;
                }
                _ => {}
            }
        }

        let decl: &str = &text[start..end];
    
        let name: String = decl
            .trim_start()
            .trim_start_matches('%') //eventualmente nel caso di parameter entities
            .trim_start()
            .chars()
            .take_while(|c| !c.is_whitespace())
            .collect();
        let value = extract_quoted(decl).unwrap_or_default();
        if !name.is_empty() {
            map.insert(name, value);
        }
        idx = end.max(start + 1);
    }
    map
}

/// estrae la prima stringa tra apici (singoli o doppi)
fn extract_quoted(s: &str) -> Option<String> {
    let q = s.find(['"', '\''])?;
    let quote = s.as_bytes()[q] as char;
    let rest = &s[q + 1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

/// numero stimato di espansioni per un'entità
// funzione ricorsiva in cui `depth` è il livello di annidamento corrente, superato `MAX_ENTITY_DEPTH` la catena viene trattata come una bomba
fn expansion_count(
    name: &str,
    ents: &HashMap<String, String>,
    memo: &mut HashMap<String, u64>,
    cap: u64,
    depth: usize,
) -> u64 {
    // interrompe la ricorsione prima di esaurire lo stack, non si memorizza questo valore perchè dipende dal percorso, non dall'entità
    if depth >= MAX_ENTITY_DEPTH {
        return cap;
    }
    if let Some(v) = memo.get(name) {
        return *v;
    }
    memo.insert(name.to_string(), 0); //vale da cache
    let value = match ents.get(name) {
        Some(v) => v.clone(),
        None => return 1,   // se name non è un'entità dichiarata allora come conta come una sola entità, non c'è nulla da espandere
    };
    let mut total: u64 = 0;
    let mut has_ref = false;
    for r in refs_in(&value) {
        has_ref = true;
        let c = if ents.contains_key(&r) {
            expansion_count(&r, ents, memo, cap, depth + 1)
        } else {
            1
        };
        total = total.saturating_add(c); // NO somma normale per gestire l'overflow degli interi
        if total >= cap {
            break;
        }
    }
    let result = if has_ref { total.max(1) } else { 1 };
    memo.insert(name.to_string(), result);
    result
}

/// trova i riferimenti a entità `&nome;` (e `%nome;`) dentro un valore
fn refs_in(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < value.len() {
        if bytes[i] == b'&' || bytes[i] == b'%' {
            if let Some(semi) = value[i + 1..].find(';') {
                let name = &value[i + 1..i + 1 + semi];
                if !name.is_empty()
                    && name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
                {
                    out.push(name.to_string());
                }
                i = i + 1 + semi + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

/// `true` se un'immagine supera il budget di pixel (difesa "huge-dimensions").
// dipendenza esterna perché i quattro formati che riconosciamo hanno layout diversi per cui scrivere e mantenere quattro parser di intestazioni 
// su input ostile vale meno della singola dipendenza piccola e a scopo unico
pub fn image_too_large(bytes: &[u8], max_pixels: u64) -> bool {
    match imagesize::blob_size(bytes) {
        Ok(size) => (size.width as u64).saturating_mul(size.height as u64) > max_pixels,
        Err(_) => false,
    }
}

/// `true` se un PDF contiene contenuto attivo (JavaScript / azioni automatiche)
pub fn pdf_has_active_content(bytes: &[u8]) -> bool {
    if !bytes.starts_with(b"%PDF-") {
        return false;
    }
    let markers: [&[u8]; 5] = [b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch"];
    markers.iter().any(|m| find_bytes(bytes, m))
}

fn find_bytes(bytes: &[u8], needle: &[u8]) -> bool { //non esiste find per i byte
    if needle.is_empty() || bytes.len() < needle.len() {
        return false;
    }
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// sniffing del tipo reale dai magic bytes
pub fn sniff_mime(bytes: &[u8]) -> Option<&'static str> {
    if bytes.len() < 4 {
        return None;
    }
    // immagini
    if bytes.starts_with(&[0x89, b'P', b'N', b'G']) {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    // documenti
    if bytes.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }
    // archivi (potenziali zip bomb)
    if bytes.starts_with(&[0x50, 0x4B, 0x03, 0x04]) {
        return Some("application/zip");
    }
    if bytes.starts_with(&[0x1F, 0x8B]) {
        return Some("application/gzip");
    }
    // HTML / XML testuale
    let head = &bytes[..bytes.len().min(512)];
    let lower = head.to_ascii_lowercase();
    let text = String::from_utf8_lossy(&lower);
    if text.contains("<!doctype html") || text.contains("<html") || text.contains("<script") {
        return Some("text/html");
    }
    if text.trim_start().starts_with("<?xml") || text.contains("<!doctype") {
        return Some("application/xml");
    }
    None
}

/// `true` se il MIME dichiarato e quello sniffato sono in conflitto pericoloso
pub fn mime_mismatch(declared: Option<&str>, sniffed: Option<&str>) -> bool {
    match (declared, sniffed) {
        (Some(d), Some(s)) => {
            let d = d.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            !d.is_empty() && d != s && base_type(&d) != base_type(&s)
        }
        _ => false,
    }
}

fn base_type(mime: &str) -> &str {
    mime.split('/').next().unwrap_or("")
}