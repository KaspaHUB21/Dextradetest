# Haertung und erfolgreiche Tests

Am 6. Oktober 2026 unter Ubuntu 24.04 in WSL getestet. Drei zusaetzliche
Agenten bearbeiteten Peer-Schutz, Job-Sicherheit und Linux/Rust-Betrieb.
Anschliessend wurden der fertige Build und die Tests gemeinsam geprueft.

| Pruefung | Ergebnis |
|---|---|
| Installer mit fixierten Cargo-Abhaengigkeiten, aktualisierte Engines | Exitcode 0 |
| Job-Sicherheit: Schema, Transcript-Bindung, Zeitfenster, feste Zeugenwahl, Annahmeliste | bestanden |
| Peer-Sicherheit: elf positive und negative Netzwerkpruefungen | bestanden |
| Rust-Pruefung: Challenge-Format und Header-Injection | bestanden |
| Zwei dauerhafte Node-Identitaeten, gegenseitige TLS-Authentifizierung | bestanden |
| A fragt echte KuCoin-API mit B als TLSNotary-Zeugen ab | bestanden |
| B startet neu, behaelt Identitaet und verbindet sich erneut | bestanden |
| B fragt echte KuCoin-API mit A als TLSNotary-Zeugen ab | bestanden |
| Beide Belege nach Abschalten beider Nodes erneut geprueft | bestanden |
| Beide Ergebnisse mit extern erwartetem Job einmalig angenommen | bestanden |
| Wiederholte Einreichung und veraenderte erwartete Challenge | abgewiesen |
| Echter Beleg nach Ablauf des Jobs, mit frischer Annahmeliste | abgewiesen |
| Falsche Node-/Peer-ID und veraenderte signierte Quittung | abgewiesen, beide Richtungen |
| Veraenderter Kurs direkt im TLSNotary-Beleg | kryptografisch abgewiesen, beide Richtungen |

Der vollstaendige Integrationstest endete mit Exitcode 0. Oeffentliche
Artefakte: `tests/results/export-run-8rlccb/report.json`. Private Testschluessel
und TLSNotary-Secrets wurden nicht in diesen Export kopiert.

Die elf Peer-Pruefungen umfassen zugelassene Verbindung, Ablehnung unbekannter
Identitaeten und signierter Adressumleitung, uebergrosse Nachrichten, falsche
Sitzungstoken, parallele Reservierung, doppelte Kanaele, autorisierte Freigabe,
Reservierungs-Ratenlimit, TCP-Limit vor dem TLS-Handshake und Erreichbarkeit
nach den Angriffstests. Bericht: `tests/results/peer-security-4tNpCp/report.json`.

Die Manipulation des TLSNotary-Belegs scheiterte an der Hash-Oeffnung gegen
die authentifizierten Commitments. Die Negativpruefung veraenderte also den
Herkunftsbeleg selbst, nicht nur eine unbeteiligte JSON-Ausgabedatei.

Beide Nodes liefen auf demselben Rechner unter demselben Betreiber. Die
echte KuCoin-API wurde ueber das Internet erreicht, die Peer-Verbindung war
lokal. Unabhaengige Betreiber, zwei externe Rechner, NAT, oeffentlicher
Bootstrap, dauerhafte Last und die systemd-Sandbox auf einem Zielserver
sind noch nicht getestet. Ein oeffentliches GitHub-Repository wurde nicht
veroeffentlicht.

Das Ergebnis ist ein gehaerteter Prototyp fuer ein ausdruecklich zugelassenes
Peer-Netz. Es ist keine unabhaengig auditierte Produktionssoftware und keine
offene, Sybil-resistente Oracle-Infrastruktur. Unterstuetzt sind ein Notar
pro API-Sitzung und der feste KuCoin-Endpunkt; Kaspa bleibt ausgeklammert.
