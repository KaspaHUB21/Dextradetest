# Haertung und erfolgreiche Tests

## Lokale Node zum externen Kasvio-Bootstrap

Am 6. Oktober 2026 wurde eine zweite Node auf dem lokalen Rechner in WSL
angelegt und gestartet. Sie verbindet sich ausgehend mit
`152.53.92.135:9443`, ohne einen oeffentlichen Listener zu behaupten.
Die lokale Peer-Liste bestaetigte die TLS-Identitaet und signierte Beschreibung
des Bootstrap; dessen Peer-Liste bestaetigte wiederum die neue Client-ID.
Es wurde keine zweite Node auf dem Server angelegt. Das vorhandene
Bootstrap-Programm wurde mit Sicherung aktualisiert und sein Dienst neu
gestartet; seine Identitaet blieb unveraendert.

Der erweiterte Discovery-Test bestand mit einem zusaetzlichen Outbound-Client:
keine private Adresse als oeffentlicher Peer, keine Aufnahme in dialbare
Gossip-Antworten, keine unberechtigte Notarreservierung. Alle elf bisherigen
Peer-Sicherheitspruefungen bestanden ebenfalls (Laeufe `discovery-G0nB4y`
und `peer-security-jgnQ46`). Dieser externe Test bestaetigt die Peer-Verbindung,
noch keinen TLSNotary-API-Job zwischen der lokalen Node und Kasvio.

## Erweiterung: offene Peer-Suche

Die neue Discovery-Schicht wurde am 6. Oktober 2026 separat geprueft:

- Drei Linux-Nodes finden sich transitive ueber A als einzigen bekannten
  Bootstrap. A braucht keine vorherigen Eintraege fuer B und C; B und C
  finden und authentifizieren einander automatisch.
- Entdeckte Teilnehmer werden nicht als vertrauenswuerdige Notare aufgenommen.
  Unberechtigte Reservierungen, Kanaele und Zeugenwahl werden abgewiesen.
- Gueltig signierte Bootstrap-Adressumleitung und private Zieladressen werden
  abgewiesen. Bestehende Pins und Teilnehmeradressen bleiben erhalten.
- Adresspolitik: 46 verbotene und 15 erlaubte IP-Faelle bestanden. Gemischte
  DNS-Antworten, Ergebnisgrenzen und acht parallele DNS-Abfragen wurden geprueft;
  ein Anwendungstimeout hebt das DNS-Limit nicht auf.
- Alle elf bisherigen Peer-Sicherheitspruefungen und die Job-Policy bestanden.
- Mit eingeschalteter `local-test`-Discovery bestanden zwei echte KuCoin-
  TLSNotary-Abfragen, Rollenwechsel, Neustart, Offline-Pruefung,
  Manipulationsabwehr, Job-Bindung, Replay-Abwehr und Ablaufpruefung.

Discovery-Lauf: `discovery-PDF8nf`; Peer-Lauf: `peer-security-R290uj`;
API-Lauf: `run-sB59MF`, alle erfolgreich. Die Exitcodes und Ergebnisse wurden
aus den Testausgaben geprueft; die Laufdateien entstanden im temporaeren
nativen Linux-Verzeichnis und wurden nicht ins Repository uebernommen.
Die API-Verbindung war echt; die Peer-Suche wurde auf Loopback getestet.
Ein oeffentlicher Bootstrap-Server und Internet-Verbindungen zwischen
verschiedenen Rechnern sind noch nicht eingerichtet bzw. getestet.

## Vorherige Haertung

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

Die fuer GitHub vorbereitete Quellversion wurde anschliessend als Git-Archiv
in ein frisches natives Linux-Verzeichnis entpackt. `setup.sh`, Job- und
Peer-Sicherheitspruefungen sowie der vollstaendige Live-Integrationstest
bestanden erneut mit Exitcode 0 (Lauf `run-JGgQAy`). Dieser Test nutzte bereits
vorhandene Node-/Rust-Laufzeiten; die automatische Erstinstallation fehlender
Laufzeiten wurde dabei nicht erneut ausgefuehrt.

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
