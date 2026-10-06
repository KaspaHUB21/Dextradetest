# Haertung und erfolgreiche Tests

## Begrenzte persistente Intervallserie mit echten API-Belegen

Der abschliessende Blackbox-Lauf `peer-jobs-XRluW5` bestand am
6. Oktober 2026 unter Ubuntu 24.04 in WSL mit Exitcode 0. Insgesamt wurden
vier echte TLSNotary-Belege erzeugt: zwei Peerjobs mit Rollenwechsel und
zwei weitere Ausfuehrungen einer Serie mit zehn Sekunden Abstand zwischen
den geplanten Startzeiten.

- Der zweite Serienjob blieb vor seiner Startzeit `pending`.
- Die Ausfuehrungsnummer stieg um eins, die geplanten Startzeiten lagen
  genau 10000 Millisekunden auseinander. Beide Challenges waren verschieden
  und ihre Job-Hashes wurden in den authentifizierten API-Anfragen geprueft.
- Die zweite API-Sitzung lag im vorgesehenen Zeitfenster; beide Ergebnisse
  wurden mit eigenem Beleg einmalig angenommen.
- Erneutes Submit derselben Basisdatei lieferte dieselben Queue-IDs und
  Job-Hashes. Intervall neun Sekunden, Anzahl 33 und eine letzte Startzeit
  mehr als zehn Minuten in der Zukunft wurden abgewiesen.
- Alle vier importierten Belege bestanden nach Abschalten der Nodes die
  Offline-Pruefung; manipulierte signierte Quittungen wurden jeweils
  abgewiesen. Auch die bisherigen Remote-Autorisierungs-, Konflikt- und
  Replay-Pruefungen bestanden.

Finaler Bericht mit oeffentlichen Artefakten:
`tests/results/export-peer-jobs-XRluW5/report.json`. Private Schluessel
und TLSNotary-Secrets sind vom Export ausgeschlossen. Serien sind auf
maximal 32 Ausfuehrungen begrenzt; dieses Beispiel ist kein Dauerabo oder
Nachweis exakter Startzeiten unter Last.

## Live-Internet: Serverjob mit lokalem Notar und delegierter Peerjob

Am 6. Oktober 2026 bestanden auch zwei Jobs zwischen dem externen
Kasvio-Server und der lokalen ausgehend verbundenen Node:

- Der Server fuehrte `fetch` aus und nutzte die lokale Node als Notar
  ueber den Rueckkanal der bestehenden Mesh-Verbindung. Der verifizierte
  Testkurs war `0.04368` USDT, Server-Job `1791305629529-19b21f11`.
- Die lokale Node uebergab mit `submit --wait true` einen Job an den Server.
  Der Server erledigte den Auftrag; die lokale Node lud den Beleg und
  pruefte ihn gegen ihren erwarteten Job. Verifiziertes Ergebnis:
  `0.04362` USDT, Job-ID `local-15a98922f753543088c8ac5b`, lokaler Import
  `received-1c331617f9a8e9ec-eebc7a1e`.

Diese Werte sind Testaufnahmen, keine aktuellen Kurse. Damit wurden echte
Internet-Peer-Verbindungen, Jobuebergabe und die Notararbeit einer lokal
ausgehend verbundenen Node praktisch bestaetigt. Beide Systeme stehen
unter demselben Betreiber; dies ist kein Unabhaengigkeitsnachweis.

Oeffentliche Internet-Belege: `tests/results/kasvio-peer-jobs`.
Die konkrete Bedienung der eingerichteten Serverinstallation steht in
`docs/KASVIO.md`.

Nach den abschliessenden Robustheitskorrekturen bestand der gesamte
Peerjob-Blackbox-Test erneut mit Exitcode 0. Finaler Bericht:
`tests/results/export-peer-jobs-uiePFk/report.json`. Er umfasst zwei echte
API-Belege, Rollenwechsel, Autorisierung, Konflikt-/Replay-Abwehr,
Offline-Pruefung und manipulierte Quittungen. Die Korrekturen betreffen
unter anderem Startreihenfolge, begrenzte eingehende Mesh-Streams und
Fehlerbehandlung beim Verbindungsaufbau; TLSNotary-Kryptografie blieb
unveraendert.

## End-to-End Peer-Jobs ueber bidirektionale Mesh-Verbindung

Am 6. Oktober 2026 bestand `tests/peer-jobs.mjs` unter Ubuntu 24.04 in WSL
mit Exitcode 0. Zwei Nodes mit verschiedenen Identitaeten fuehrten echte
KuCoin-KAS-USDT-Jobs in beiden Richtungen aus. B bewirbt keine Adresse
(`address: null`, `dialable: false`) und verbindet sich ausgehend mit A;
der persistente Link transportiert auch Rueckkanal und Notararbeit.

- Ohne Zeugenfreigabe wurde A's API-Abfrage abgewiesen.
- Nach ausdruecklichem gegenseitigem `trust-peer` uebergab B einen Job an A.
  A arbeitete mit B als Notar ueber die Rueckrichtung des Mesh-Links.
  Submit, Status und Ergebnisdownload lieferten einen echten gueltigen Beleg.
- Erneuter identischer Submit lieferte dieselbe Queue-ID; eine veraenderte
  Challenge derselben Ausfuehrung wurde abgewiesen. Doppelte Live-Annahme
  durch `job-result` wurde als Replay abgewiesen.
- Eine dritte nicht zugelassene Node C konnte trotz bekannter Queue-ID und
  gefaelschtem lokalem Submission-Datensatz weder Jobs einreichen noch fremde
  Status-/Ergebnisdaten abrufen. Die Remote-Autorisierung blieb wirksam.
- A uebergab anschliessend einen Job an B. `--wait true` lud und pruefte den
  zweiten echten Beleg automatisch; Worker- und Notarrollen waren vertauscht.
- Beide importierten Belege bestanden nach Abschalten aller Nodes die
  historische Offline-Pruefung. Eine manipulierte signierte Quittung wurde
  in beiden Richtungen abgewiesen.

Beide echten API-Abfragen lieferten `0.04366` USDT; dieser Wert ist eine
Testaufnahme, kein aktueller Kurs. Bericht und oeffentliche Artefakte:
`tests/results/export-peer-jobs-OJ6YHq/report.json`. Private Schluessel und
TLSNotary-Secrets wurden vom Export ausgeschlossen. Die Peer-Verbindungen
waren lokal; die API-Abfragen erfolgten ueber das Internet. Dieser Test
belegt weder unabhaengige Betreiber noch ein offenes Sybil-sicheres Netzwerk.

## Echter Job: lokale Node und externer Kasvio-Notar

Am 6. Oktober 2026 fuehrte die lokale WSL-Node einen KAS-USDT-Job mit dem
externen Notar `152.53.92.135:9443` aus. KuCoin lieferte `0.04378` USDT.
Der TLSNotary-Beleg wurde gegen Job und beide erwarteten Identitaeten
geprueft und einmalig angenommen. Erneute Einreichung scheiterte mit
`Replay rejected: job execution or TLS proof already consumed`.
Oeffentliche Belegdateien liegen lokal unter `tests/results/kasvio-live-job`;
private Schluessel und TLSNotary-Secrets wurden nicht exportiert.

Fuer diesen Job wurde die lokale Identitaet gezielt als eingehender Client
auf dem Notar zugelassen. Sie ist dadurch kein vertrauenswuerdiger Notar.
Der neue Zulassungs-/Widerrufstest und alle elf Peer-Sicherheitspruefungen
bestanden zuvor (`discovery-6HxT5M`, `peer-security-VSG9sU`).

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
Damals waren ein oeffentlicher Bootstrap-Server und Internet-Verbindungen
zwischen verschiedenen Rechnern noch nicht eingerichtet bzw. getestet.
Die spaeteren Live-Internet-Tests sind oben gesondert dokumentiert.

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
# Abschlusspruefung auf zwei Systemen

Die finale Intervallversion wurde am 6. Oktober 2026 auf dem oeffentlichen
Server `152.53.92.135:9443` und der lokalen Outbound-Node aktiviert.
Eine vom lokalen Auftraggeber eingereichte Serie mit zwei Ausfuehrungen
und zehn Sekunden Abstand wurde vom Server ausgefuehrt und lokal mit
`verified: true`, `accepted: true` geprueft. Job-ID:
`local-eda36652c8dc18dcabd7a5d0`; Ausfuehrungen 0 und 1; historische
Testwerte `0.04335` und `0.04333` USDT. Die lokale Node diente als Notar
ueber den Rueckkanal, ohne oeffentliche Listener-Adresse.

Die vier Lifecycle-Regressions bestanden nach der letzten Korrektur:
blockierter Broker, blockierter Peer-Port, zweiter Daemon und sauberer
Neustart/Shutdown. Private Daten blieben unveroeffentlicht.
