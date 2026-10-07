# Oracle-Node-Prototyp fuer Linux

Zwei identische Installationen koennen sich gegenseitig finden, eine
verschluesselte Peer-Verbindung aufbauen und abwechselnd als API-Abfrager
oder TLSNotary-Zeuge arbeiten. Keine Kaspa-Anbindung in diesem Prototyp.

Aktueller Funktions- und Testumfang: [Abschlussbericht](COMPLETION-REPORT.md).
Transportgrenzen: [Netzwerk](NETWORK.md). Vertrauensannahmen:
[Sicherheitsmodell](SECURITY.md). Das ist ein getesteter Prototyp mit
zugelassenen Notaren, keine Garantie absoluter Sicherheit.

## Was implementiert ist

- Dauerhafte Ed25519-Node-Identitaet und selbst ausgestelltes TLS-Zertifikat.
- Peer-Verkehr ueber gegenseitiges TLS 1.3. Statt einer zentralen CA wird
  der SHA-256-Fingerabdruck des oeffentlichen Identitaetsschluessels geprueft.
- Signierte Peer-Beschreibungen binden Node-ID, Adresse und den separaten
  secp256k1-Notarschluessel aneinander.
- Drei Discovery-Modi: `closed` fuer vorab zugelassene Peers,
  `public` fuer signierte Teilnehmerbeschreibungen ueber oeffentlich
  routbare Adressen und `local-test` fuer numerische Loopback-Adressen.
  Ein bekannter Bootstrap mit authentisch erhaltener Node-ID vermittelt
  weitere erreichbare Peers. Die Node prueft Verbindungen und verbindet
  sich mit begrenzter Parallelitaet erneut.
- Neue Installationen nutzen standardmaessig `public` und den eingebauten
  Bootstrap `kasvio.network:9443` mit fest gepinnter Node-ID
  `bc1886af011f62966d09dce0441216b83078e55258fd68e5f83510ba0e516188`.
  Ohne `--address` ist die Node ausgehend verbunden und braucht keine
  Portfreigabe. Explizite Loopback-Adressen behalten den Modus `closed`;
  `--discovery closed` oder `--discovery local-test` deaktiviert den Anker.
  Bestehende Datenverzeichnisse werden durch ein Update nicht umkonfiguriert.
  Der Server bewirbt derzeit `152.53.92.135:9443`; ausschliesslich dieser
  feste Adressalias ist fuer den gepinnten Domain-Anker zusaetzlich erlaubt.
  Der einzelne Bootstrap muss erreichbar sein; weitere Anker koennen mit
  `add-bootstrap` hinzugefuegt werden. Ein anderer Schluessel wird abgewiesen.
- Discovery-Bootstraps und zugelassene Zeugen sind getrennt: `add-bootstrap`
  erlaubt Peer-Suche, `add-seed` erlaubt Zusammenarbeit bei TLSNotary-Jobs.
  Ein entdeckter Peer wird dadurch nicht automatisch zum Zeugen.
- Der neue oeffentliche Standard aktiviert einen bekannten, exakt gepinnten
  ersten Notar (Node-ID UND Notarschluessel), oeffentliche begrenzte
  Job-Annahme und Notarsitzungen. Das ist eine explizite mitgelieferte
  Vertrauensliste, kein Vertrauen in beliebige entdeckte Identitaeten.
  Weitere Notare kommen durch Betreiber-Pins oder zeitlich begrenzte,
  mehrfach signierte Notarlisten hinzu. Widerruf und Ablauf gelten auch
  fuer laufende Dienste und werden vor Ergebnisannahme erneut geprueft.
- API-Jobs waehlen kryptografisch zufaellig einen erreichbaren explizit
  zugelassenen Zeugen. Die Wahl wird vor Kontakt dauerhaft fuer den Job
  gespeichert; ist dieser Zeuge spaeter nicht erreichbar, scheitert der Job.
  Es wird nicht erneut gewuerfelt. Lokaler Zufall ist keine netzwerkweit
  nachpruefbare oder Sybil-resistente Auswahl.
  Entdeckte Identitaeten werden nicht automatisch zu vertrauenswuerdigen Notaren.
- API-Jobs v2 unterstuetzen oeffentliche HTTPS-GET-JSON-Endpunkte auf Port443.
  Alle DNS-Adressen werden auf private/reservierte Ziele geprueft; gewaehlt
  wird anschliessend eine gepruefte numerische Adresse. POST, Zugangsdaten,
  eigene Header, Redirects und Antworten ueber 16KiB werden nicht unterstuetzt.
  MPC-, Kontroll- und
  Weiterleitungskanal laufen innerhalb der authentifizierten Peer-Verbindung.
  Eine zeitlich begrenzte Reservierung bindet alle drei Kanaele an denselben
  Peer und verhindert eine parallele Vermischung von Jobs.
- Vollstaendiger TLSNotary-Beleg fuer den KAS-USDT-Ticker. Zusaetzlich signiert
  die abfragende Node eine Quittung mit Node-ID, Peer-ID, Beleg-Hash und Kurs.
- Spaetere Pruefung von Node-Quittung und TLSNotary-Beleg ohne laufende Nodes
  oder erneute API-Abfrage.
- Ein Job-Hash wird in der authentifizierten HTTP-Anfrage uebertragen.
  Die signierte Quittung bindet Job, Anfrage, Antwort und Herkunftsbeleg.
- Zeitfenster und dauerhafte Annahmeliste verhindern bei der Job-Annahme
  abgelaufene und mehrfach eingereichte Ergebnisse.
- Verbindungs-/Ratenlimits, Nachrichten-/Dateigrenzen, Kanalreservierungen,
  Prozess-Zeitlimits und begrenzte Logs schuetzen die lokalen Ressourcen.
- Dauerhafte gegenseitig authentifizierte Mesh-Verbindungen transportieren
  Kontrollnachrichten und Kanaele in beide Richtungen. Eine Node ohne
  beworbene oeffentliche Adresse kann ueber ihren ausgehenden Link auch
  explizit als Zeuge zugelassen werden.
- Ausgehende Nodes hinter NAT lernen einander ueber signierte Beschreibungen
  und verbinden sich ueber einen begrenzten Vermittlungsweg mit innerem
  gegenseitigem TLS1.3. Der Vermittler erhaelt keinen Klartext und kann
  keine andere Node-Identitaet vortaeuschen. Mehrere Einstiegspunkte sind
  konfigurierbar; das Standardnetz hat noch keinen DHT oder beliebige
  Mehrsprung-Routen und seine Ressourcenlimits sind endlich.
- Peer-Jobs: `submit`, `job-status` und `job-result` uebertragen einen Auftrag,
  verfolgen dessen dauerhaften Zustand und importieren den geprueften Beleg.

## Installation auf Linux

### Einfacher Start unter Ubuntu 24.04

Das oeffentliche Repository klonen oder dessen ZIP herunterladen und entpacken.

```bash
git clone https://github.com/KaspaHUB21/Dextradetest.git
cd Dextradetest
sudo apt update
sudo apt install -y build-essential openssl ca-certificates curl xz-utils git
bash setup.sh
```

`setup.sh` nutzt vorhandenes Node.js 22+ und Rust 1.85+ oder laedt fehlende
Laufzeiten nach `.tools/`: Node.js 24.19.0 und Rust 1.99.0. Downloads kommen
von den offiziellen Node-/Rust-Servern und werden gegen deren SHA-256-Dateien
geprueft. Diese Pruefung setzt Vertrauen in die HTTPS-Quelle voraus; sie ist
keine unabhaengige Release-Signatur. Das Setup veraendert keine Shell-Profile
und installiert keinen Systemdienst. Der erste Rust-Build kann dauern.
Das Setup unterstuetzt Linux x86_64 und aarch64; getestet wurde x86_64.

Danach kann statt `node oracle-node.mjs` immer `./oracle-node` benutzt werden:

```bash
umask 077
./oracle-node init --data "$HOME/oracle-node-data"
./oracle-node start --data "$HOME/oracle-node-data"
```

Eine API-Abfrage braucht einen anderen zugelassenen Notar. Im neuen
oeffentlichen Profil ist der bekannte erste Notar bereits enthalten.
Er muss laufen und die aktuelle Node-Version verwenden. Als Job-Worker
braucht dieser erste Notar selbst einen anderen zugelassenen Notar.
Die Verbindung zum Discovery-Anker und weitere Peer-Suche starten automatisch.
Fuer einen oeffentlich erreichbaren Peer bei `init` zusaetzlich
`--address HOST:9443 --listen 0.0.0.0:9443` angeben und den Port freigeben.
Bestehende Installationen koennen das neue Profil ohne Schluesselwechsel
aktivieren. Zuerst Quellstand und Engines aktualisieren, dann:

```bash
./oracle-node network-enable --data /pfad/node-data
# Danach den laufenden Node-Dienst neu starten.
```

Oeffentliche Discovery setzt eine ausgehende Node oder eine oeffentlich
beworbene Adresse voraus; eine beworbene Loopback-Adresse ist nicht geeignet.
Tests: `node tests/default-bootstrap.mjs`; mit gebauten Engines und Internet
zusaetzlich `node tests/public-bootstrap.mjs` (frische temporaere Identitaet).

### Einen API-Job erzeugen, ausfuehren und sehen

Vorlagen unter [templates](templates/README.md) enthalten Beispiele fuer
KuCoin BTC und Coinbase BTC sowie das Schema. `job-create` ersetzt die
Beispielkennung, Challenge und Zeitfenster durch einen frischen Auftrag:

```bash
./oracle-node status --data "$HOME/oracle-node-data"
./oracle-node job-create --template templates/kucoin-btc.job.json --out "$HOME/btc-job.json"
./oracle-node fetch --data "$HOME/oracle-node-data" --job-spec "$HOME/btc-job.json"
```

Die Ausgabe enthaelt `verified`, `values` und den gespeicherten Belegordner
`job`. `status` trennt beobachtete Peers, aktuelle Verbindungen und
zugelassene bereitstehende Notare. Fuer einen anderen frisch authentifizierten
Worker aus dieser Liste:

```bash
./oracle-node submit --data "$HOME/oracle-node-data" --peer-id WORKER_NODE_ID \
  --job-spec "$HOME/btc-job.json" --wait true
```

Die Antwort wird erst nach unabhängiger Pruefung des kompletten TLSNotary-
Belegs und der zugelassenen Notaridentitaet angenommen. Oeffentliche neue
Auftraege sind auf vier pro Minute insgesamt und zwei pro Identitaet begrenzt;
Serien brauchen eine explizite Freigabe. Ein Peer wird dadurch nicht zum Notar.
`network-enable --public-jobs false --public-notary false --witness-trust pinned`
deaktiviert diese Dienste und die mitgelieferte Notarfreigabe (Dienst neu starten).

### Erweiterbare Notarliste

Ein Betreiber kann einen frisch authentifizierten Peer mit `trust-peer`
freigeben. Fuer gemeinsame Listen liest `policy-configure` eine lokal
vertraute Autoritaetsdatei `{ "authorities": ["PEM...", "PEM..."], "threshold": 2 }`
und eine von diesen Schluesseln ausreichend signierte Policy:

```bash
./oracle-node policy-configure --data "$HOME/oracle-node-data" \
  --trust-file authority-trust.json --policy-file signed-witness-policy.json
```

Signaturformat und Hilfsfunktionen stehen in `witness-policy.mjs`,
ein vollstaendiges Zwei-Autoritaeten-Beispiel in `tests/witness-policy.mjs`.
Autoritaets-Pins muessen unabhaengig abgestimmt werden. Die Node erzeugt
keine angeblich unabhaengigen Autoritaeten automatisch. Neue gueltig signierte
Listen koennen dieselben lokalen Pins verwenden; alte Sequenzen, widerspruechliche
Listen derselben Sequenz und abgelaufene Listen scheitern. Verteilung und
Betreiberzulassung sind bisher Verwaltungsaufgaben, keine offene Sybil-Abwehr.
Die folgenden Abschnitte beschreiben den Austausch der IDs und beide Rollen.
Fuer Updates: beide Dienste stoppen, den gewuenschten Quellstand herunterladen
und `bash setup.sh --replace-binaries` ausfuehren. Private Daten ausserhalb des
Repository-Ordners halten. Automatische Updates und Rollback gibt es nicht.

### Build mit vorhandenen Laufzeiten

Voraussetzungen: Node.js 22+, aktuelles Rust/Cargo mit Edition-2024-Unterstuetzung,
OpenSSL, GCC/Build-Werkzeuge und Internet fuer die Build-Abhaengigkeiten.
Getestet unter Ubuntu 24.04 x86_64 in WSL.

```bash
bash install.sh
```

Der Installer baut vier native Hilfsprogramme und legt sie lokal in `bin/`
ab. Er installiert keinen globalen Dienst, aendert keine Firewall und braucht
keine Administratorrechte. Die offiziellen TLSNotary-Quellen sind versioniert
in `vendor/tlsn` enthalten; `tlsn-engine/Cargo.lock` fixiert die Abhaengigkeiten.

Repository: https://github.com/KaspaHUB21/Dextradetest (privat).
Ein oeffentliches Release und signierte Downloadpakete gibt es noch nicht.

### Privater Linux-Betrieb und Updates

Vor Initialisierung `umask 077` setzen. Fuer den Dauerbetrieb einen eigenen
unprivilegierten Benutzer und ein privates Datenverzeichnis mit Modus 0700
verwenden. Der Launcher startet eine schon initialisierte Node mit
bereinigter Umgebung und kontrollierten Engine-Pfaden:

```bash
bash deploy/run-node.sh /absoluter/pfad/node-data
```

`deploy/oracle-node.service` ist ein **manuell einzurichtendes Beispiel**
fuer systemd. Es erwartet Programm/Binaries unter `/opt/oracle-node`,
Node.js unter `/usr/bin/node`, den Benutzer/die Gruppe `oracle-node` und
bereits initialisierte Daten unter `/var/lib/oracle-node`. Diese Pfade
vor Benutzung anpassen und gegen die installierten Runtime-Pfade pruefen.
Programm/Binaries gehoeren dem Administrator, Daten dem Dienstbenutzer.
Die Unit erstellt keine Node-Identitaet und setzt keine Peers automatisch.
Sie beschraenkt Schreibzugriff auf das Datenverzeichnis, entfernt
Capabilities und begrenzt Speicher, CPU und Prozesse. Die Kompatibilitaet
der Sandbox muss auf dem Zielsystem vor Dauerbetrieb getestet werden.

Der Installer bewahrt bestehende Binaries. Fuer einen bewussten Update:
Dienst stoppen, den geprueften Quellstand verwenden, dann
`bash install.sh --replace-binaries` ausfuehren und lokal testen, bevor
der Dienst wieder startet. Identitaeten werden dabei nicht ersetzt.
Ein Cargo-Lockfile ist kein Nachweis fuer die Echtheit eines Releases.
Siehe [SECURITY.md](SECURITY.md) fuer Vertrauensannahmen und Betriebsgrenzen.

## Zwei Nodes starten

Node A einmalig initialisieren:

```bash
node oracle-node.mjs init --data ./node-a \
  --address 127.0.0.1:19443 --notary-port 19047
```

Node B einmalig initialisieren:

```bash
node oracle-node.mjs init --data ./node-b \
  --address 127.0.0.1:20443 --notary-port 20047
```

Beide Befehle geben die jeweilige Node-ID aus. Diese IDs vorab authentisch
austauschen; **nicht** ungeprueft von einem unbekannten Netzwerkdienst beziehen.
Dann die jeweilige Gegenstelle explizit konfigurieren:

```bash
node oracle-node.mjs add-seed --data ./node-a \
  --address 127.0.0.1:20443 --id NODE_ID_B
node oracle-node.mjs add-seed --data ./node-b \
  --address 127.0.0.1:19443 --id NODE_ID_A
```

In zwei Terminals starten:

```bash
node oracle-node.mjs start --data ./node-a
node oracle-node.mjs start --data ./node-b
```

In einem weiteren Terminal:

```bash
node oracle-node.mjs peers --data ./node-a
node oracle-node.mjs fetch --data ./node-a
node oracle-node.mjs fetch --data ./node-b
```

`fetch` gibt den Job-Ordner und das gepruefte Ergebnis als JSON aus.
Jeder Job bekommt einen eigenen Ordner unter `node-a/jobs` oder `node-b/jobs`.
Mit `fetch --job-spec /pfad/job.json` kann der Auftraggeber einen festen Job
vorgeben. Ohne diese Option entsteht ein lokaler Testjob. Das Schema steht in
`jobs.mjs`: ID, Ausfuehrungsnummer, zufaellige Challenge, Zeitfenster von maximal
zehn Minuten und der fest unterstuetzte API-Endpunkt.

## Erneute Pruefung

```bash
node oracle-node.mjs verify --job /pfad/zum/job \
  --node-id NODE_ID_DES_ABFRAGERS --peer-id NODE_ID_DES_ZEUGEN
```

Die beiden erwarteten IDs muessen vorab bekannt und akzeptiert sein. Der
Pruefer vertraut nicht einfach einem beliebigen Schluessel im Beleg. Er prueft
die signierten Beschreibungen gegen diese IDs, die Node-Quittung, den Beleg-Hash
und die TLSNotary-Presentation einschliesslich Serveridentitaet und aller
Anfrage-/Antwortbytes. Den oeffentlichen Export kann er aus dem Beleg neu erzeugen.

Dieser Befehl ist eine historische Pruefung (`accepted: false`), auch nach
Ablauf des Jobs. Fuer eine neue, einmalige Annahme muss der Pruefer den Auftrag
aus seiner eigenen vertrauenswuerdigen Quelle angeben:

```bash
node oracle-node.mjs verify --job /pfad/zum/job \
  --node-id NODE_ID_DES_ABFRAGERS --peer-id NODE_ID_DES_ZEUGEN \
  --expected-job /pfad/erwarteter-job.json --state /privater/pfad/annahmen.json
```

Die Annahmeliste muss dauerhaft erhalten bleiben. Ihre Loeschung oder ein
anderer Listenpfad hebt die lokale Replay-Abwehr auf. Bei einem Absturz kann
eine Sperrdatei verbleiben: Dienst stoppen und den Zustand kontrolliert
wiederherstellen. Linux-Schluessel muessen Modus 0600 haben; unter WSL Daten
auf dem nativen Linux-Dateisystem ablegen, nicht auf einem Windows-Laufwerk.
`remove-seed` entfernt einen zugelassenen Peer; fuer eingehende Verbindungen
den Dienst danach neu starten. `renew-cert` erneuert das Zertifikat unter
derselben Identitaet und erfordert ebenfalls einen Neustart.

## Einen Job an einen Peer uebergeben

Fuer die bereits eingerichtete Kasvio-Installation stehen konkrete
Serverbefehle unter [docs/KASVIO.md](docs/KASVIO.md).

Die Nodes muessen laufen und ueber einen authentifizierten Link verbunden
sein. Ein bereits bekannter signierter Peer kann nach Pruefung seiner ID
ausdruecklich zugelassen werden. Beispiel: A und B haben sich ueber Bootstrap
gefunden; A soll ausfuehren und B soll bezeugen:

```bash
./oracle-node trust-peer --data /pfad/node-a --id NODE_ID_B
./oracle-node trust-peer --data /pfad/node-b --id NODE_ID_A
```

Danach beide Dienste neu starten. `trust-peer` uebernimmt den bereits
authentifizierten Descriptor einschliesslich Notarschluessel; die Freigabe
ist eine Vertrauensentscheidung des Betreibers. Sie wird nicht automatisch
aus Discovery abgeleitet. Fuer B ohne beworbene Adresse ist A's bestehender
Mesh-Link der Rueckkanal. B bleibt `address: null` und `dialable: false`.

Auf B einen Auftrag an A senden:

```bash
./oracle-node submit --data /pfad/node-b --peer-id NODE_ID_A \
  --job-spec /pfad/erwarteter-job.json
./oracle-node job-status --data /pfad/node-b --peer-id NODE_ID_A \
  --queue-id QUEUE_ID_AUS_SUBMIT
./oracle-node job-result --data /pfad/node-b --peer-id NODE_ID_A \
  --queue-id QUEUE_ID_AUS_SUBMIT
```

`submit` liefert `queueId`, `status` und `jobHash` und speichert den
erwarteten Auftrag lokal unter `submitted-jobs/`. Ohne `--job-spec` wird
ein lokaler KuCoin-Testauftrag erzeugt. Statuswerte sind `pending`, `running`,
`completed` und `failed`. Nur der zugelassene urspruengliche Auftraggeber
kann den Status oder Ergebnisbeleg abrufen. Eine bekannte Queue-ID allein
erteilt keine Zugriffsberechtigung.

`job-result` speichert den oeffentlichen Beleg in einem eigenen `jobs/`-
Unterordner und prueft ihn gegen die lokal beim Submit gespeicherte
Spezifikation, Worker-Identitaet und zugelassenen Notar. Ein Job wird nur
einmal in der lokalen Annahmeliste akzeptiert. Die eigenen Spezifikationen
und diese Liste dauerhaft bewahren; sie sind die lokale Vertrauensgrundlage.

Mit Warteoption erfolgt die Statusabfrage und Ergebnispruefung automatisch:

```bash
./oracle-node submit --data /pfad/node-b --peer-id NODE_ID_A \
  --job-spec /pfad/erwarteter-job.json --wait true
```

Die Queue persistiert Auftraege. Derselbe Auftrag vom selben Auftraggeber
liefert beim erneuten Submit dieselbe Queue-ID und wird nicht erneut
ausgefuehrt. Eine veraenderte Spezifikation derselben Job-ID/Ausfuehrung
wird abgewiesen. Wartende Auftraege koennen nach Neustart fortfahren;
unterbrochene laufende Ausfuehrungen werden als fehlgeschlagen markiert,
statt bei unklarem Zustand automatisch erneut abzufragen.

### Eine begrenzte Intervallserie

```bash
./oracle-node submit --data /pfad/node-b --peer-id NODE_ID_A \
  --interval-seconds 10 --count 2 --wait true
```

Dieser Auftrag umfasst zwei getrennte API-Abfragen mit zehn Sekunden
Abstand zwischen ihren geplanten Startzeiten. `--count` ist auf hoechstens
32 Ausfuehrungen begrenzt; das Intervall muss mindestens zehn Sekunden
betragen, die letzte geplante Startzeit darf hoechstens zehn Minuten in
der Zukunft liegen. Die Optionen werden gemeinsam verwendet. Optional
kann `--job-spec` eine Ausgangsspezifikation vorgeben.

Jede Ausfuehrung bekommt eine eigene Challenge, eine erhoehte
Ausfuehrungsnummer und einen eigenen TLSNotary-Beleg. Weitere Challenges
werden kryptografisch aus der zufaelligen Basis-Challenge und der
Ausfuehrungsnummer abgeleitet. Derselbe Basisauftrag liefert beim Retry
dieselben Bindungen und Queue-IDs; es wird nicht neu gewuerfelt.
Die Serie wird als
zusammengehoeriger Batch persistent angenommen. Ohne `--wait true` liefert
Submit `jobs` mit den einzelnen Queue-IDs; Status und Beleg werden pro
Queue-ID abgefragt. Mit Warteoption liefert die Ausgabe `results` mit den
geprueften und einmalig angenommenen Einzelergebnissen. Einzeljobs behalten
ihre bisherige Ausgabe.

Die Queue arbeitet seriell. Eine geplante Startzeit ist eine untere
Zeitgrenze; Last und vorherige Jobs koennen den tatsaechlichen Start
verzoegern. Ein verpasstes Ausfuehrungsfenster fuehrt zum Fehler. Dies ist
eine begrenzte Serie, kein unbegrenztes Dauerabo oder allgemeiner Scheduler.

Der Daemon besitzt die Queue ueber `job-queue.owner`. Nach einem harten
Absturz kann dieser Marker verbleiben. Den tatsaechlich gestoppten alten
Prozess und dessen PID pruefen, dann die explizite Wiederherstellung nutzen:

```bash
./oracle-node queue-recover --data /pfad/node-a --pid ALTE_PROZESS_ID
```

Keine Marker oder Replay-Listen waehrend laufendem Betrieb loeschen. Die
CLI kommuniziert mit dem eigenen identitaetsgebundenen Loopback-Broker auf
`notaryPort + 3`; alle vier internen Ports muessen frei sein und bleiben
lokal. Dies ist kein oeffentlicher HTTP-Administrationsdienst.

## Verbindung ueber das Internet

### Lokale Node hinter einem Router

Eine Node ohne oeffentlichen Listener kann sich ausgehend mit dem Bootstrap
verbinden. Sie veroeffentlicht keine erfundene oder private Peer-Adresse:

```bash
./oracle-node init --data "$HOME/oracle-local-data" \
  --outbound-only true --listen 127.0.0.1:19443 --discovery public
./oracle-node add-bootstrap --data "$HOME/oracle-local-data" \
  --address 152.53.92.135:9443 --id BESTAETIGTE_BOOTSTRAP_NODE_ID
./oracle-node start --data "$HOME/oracle-local-data"
```

Der Bootstrap muss die aktuelle Version mit Unterstuetzung fuer
`outboundOnly` ausfuehren. Der signierte Client-Descriptor enthaelt
`address: null`; Client-Zertifikat und Signatur werden geprueft. Der
Bootstrap waehlt den Client nicht fuer Rueckverbindungen und gibt ihn
nicht als dialbaren Peer weiter. Die Peer-Liste kennzeichnet `dialable`
und `trusted` getrennt. Ueber den dauerhaften Mesh-Link sind nach
ausdruecklicher Zulassung auch Peer-Jobs und Notararbeit in beide
Richtungen moeglich; eine Notarberechtigung entsteht durch Discovery nicht.

Fuer einen API-Job den oeffentlichen Notar auf dem Client mit `add-seed`
zulassen. Der Notar kann genau diese ausgehende Client-Identitaet fuer
Anfragen freigeben, ohne sie als Notar zu behandeln:

```bash
# Auf dem Notar, danach dessen Dienst neu starten:
./oracle-node allow-client --data /pfad/notar-daten --id CLIENT_NODE_ID
# Auf dem Client:
./oracle-node add-seed --data "$HOME/oracle-local-data" \
  --address 152.53.92.135:9443 --id BESTAETIGTE_BOOTSTRAP_NODE_ID
./oracle-node fetch --data "$HOME/oracle-local-data"
```

`remove-client --data /pfad/notar-daten --id CLIENT_NODE_ID` widerruft die
Freigabe nach einem Dienstneustart. Hoechstens 32 Client-IDs sind erlaubt;
sie werden weder zur Zeugenliste noch zu ausgehenden Verbindungszielen.

### Oeffentlich erreichbare Teilnehmer

Die gleichen Programme unterstuetzen DNS-Namen oder IP-Adressen. Fuer einen
erreichbaren Host beispielsweise bei `init` eine oeffentlich erreichbare
Adresse und einen Listen-Socket angeben:

```bash
node oracle-node.mjs init --data ./node-data \
  --address oracle.example.org:9443 --listen 0.0.0.0:9443 --discovery public
node oracle-node.mjs add-bootstrap --data ./node-data \
  --address bootstrap.example.org:9443 --id NODE_ID_DES_BOOTSTRAPS
node oracle-node.mjs start --data ./node-data
```

Das sind Platzhalter, keine existierenden Bootstrap-Dienste. Die ID ist der
64-stellige kleingeschriebene Hex-Fingerabdruck der Node-Identitaet und muss
authentisch erhalten werden. Bootstrap-Betreiber starten dieselbe Software
mit `--discovery public`, einer oeffentlich routbaren Adresse und einem
erreichbaren Listen-Port. Der Peer-Port
muss vom anderen Rechner erreichbar sein; NAT/Firewall/Portweiterleitung
werden nicht automatisch konfiguriert. Die drei internen Rust-Ports und
der CLI-Broker bleiben auf Loopback und werden nicht ins Internet gestellt.

Es gibt noch kein offenes Oracle-Netz mit automatisch vertrauenswuerdigen
Teilnehmern. Der Kasvio-Testserver dient als bekannter Einstiegspunkt fuer
ausdruecklich eingerichtete Tests. Mindestens ein bekannter lebender,
erreichbarer Bootstrap ist fuer die erste Peer-Suche erforderlich. Weitere
Peers werden durch signierte Beschreibungen bekannt; damit kann das Netz
nach dem Einstieg weitere Verbindungen aufbauen. Eine lokale Outbound-Node
und der externe Kasvio-Server haben Internet-Peerjobs und Notararbeit ueber
den Rueckkanal erfolgreich ausgefuehrt. Beide gehoeren demselben Betreiber.
Unabhaengige Betreiber und allgemeine NAT-Verfuegbarkeit wurden damit
nicht bestaetigt; Details stehen in [TESTERGEBNIS.md](TESTERGEBNIS.md).

`public` nimmt neue Discovery-Verbindungen an, nachdem Zertifikatsidentitaet
und signierte Peer-Beschreibung geprueft wurden. Vor einem ausgehenden Dial
werden DNS-Ergebnisse auf global routbare IP-Adressen geprueft und die
gepruefte IP fuer genau diese Verbindung verwendet. Private, lokale und
reservierte Ziele werden dabei ausgeschlossen. Dies verhindert, dass ein
neu entdeckter Peer die Node zu internen Diensten umleitet. `local-test`
erlaubt fuer Discovery ausschliesslich numerische Loopback-Adressen.

Ein Discovery-Bootstrap erhaelt keine automatische Berechtigung fuer
Notarjobs. `reserve`, `channel` und `release` bleiben zugelassenen Seeds mit
passender ID und exakt konfigurierter Adresse vorbehalten. Fuer eine echte
TLSNotary-Abfrage muessen beide beteiligten Nodes die jeweils andere mit
`add-seed` zulassen. Eine oeffentliche Peer-Liste ist keine Vertrauensliste.

Die Peer-Liste ist auf 64 Teilnehmer, davon hoechstens 32 nicht vorab konfigurierte,
begrenzt; maximal acht Discovery-Bootstraps sind konfigurierbar. Erreichbarkeit
und Wiederverbindung werden begrenzt geprueft. NAT-Traversal, Relay-Dienste
und automatische Firewall-/Portweiterleitung gibt es nicht.
Nicht erreichbare entdeckte Teilnehmer werden nach zwei Minuten entfernt.
Pro Suchrunde werden hoechstens zwoelf Teilnehmer in Vierergruppen geprueft,
und neue Gruppen nach 15 Sekunden nicht mehr begonnen. Pro Antwort werden
hoechstens vier neue Beschreibungen aufgenommen. DNS-Abfragen sind auf acht
gleichzeitige Betriebssystem-Abfragen begrenzt, auch wenn die Anwendung nach
drei Sekunden aufhoert zu warten. Fehlerhafte Peers erhalten Wartezeiten bis
zu einer Minute. Diese Grenzen bieten keinen Schutz gegen beliebig viele
Angreifer oder gegen eine komplett manipulierte Bootstrap-Teilnehmerliste.

Modus oder Einstiegspunkte aendern:

```bash
node oracle-node.mjs discovery --data ./node-data --mode closed
node oracle-node.mjs remove-bootstrap --data ./node-data --id NODE_ID_DES_BOOTSTRAPS
```

Nach Konfigurationsaenderungen den laufenden Dienst neu starten. `closed`
beschraenkt den Teilnehmerkreis wieder auf ausdruecklich zugelassene Peers.

## Drei Nodes finden sich lokal

Dieses Beispiel testet Peer-Suche und verbindet noch keine Notarjobs.
Die Daten im privaten Linux-Dateisystem ablegen. Node A ist der gemeinsame
Einstiegspunkt; B und C brauchen jeweils nur dessen Bootstrap-ID.

```bash
umask 077
node oracle-node.mjs init --data ./discover-a --address 127.0.0.1:19443 \
  --notary-port 19047 --discovery local-test
node oracle-node.mjs init --data ./discover-b --address 127.0.0.1:20443 \
  --notary-port 20047 --discovery local-test
node oracle-node.mjs init --data ./discover-c --address 127.0.0.1:21443 \
  --notary-port 21047 --discovery local-test
node oracle-node.mjs add-bootstrap --data ./discover-b \
  --address 127.0.0.1:19443 --id NODE_ID_A
node oracle-node.mjs add-bootstrap --data ./discover-c \
  --address 127.0.0.1:19443 --id NODE_ID_A
```

`NODE_ID_A` durch die bei A ausgegebene ID ersetzen. In drei Terminals starten:

```bash
node oracle-node.mjs start --data ./discover-a
node oracle-node.mjs start --data ./discover-b
node oracle-node.mjs start --data ./discover-c
```

Danach in einem weiteren Terminal `node oracle-node.mjs peers --data
./discover-b` aufrufen. Nach dem Peer-Austausch kann B auch C kennenlernen
und umgekehrt; gegenseitige Bootstrap-Pins sind dafuer nicht erforderlich.
Fuer anschliessende API-Abfragen A und B wie im Abschnitt "Zwei Nodes
starten" gegenseitig mit `add-seed` zulassen und neu starten. Lokale
Discovery ist ein Netzwerktest; sie belegt keine unabhaengigen Betreiber.

## Automatischer Test

```bash
node tests/discovery-address.mjs
node tests/default-bootstrap.mjs
node tests/discovery-network.mjs
node tests/job-security.mjs
node tests/peer-security.mjs
node tests/integration.mjs
node tests/peer-jobs.mjs
# API-Belege bei eingeschalteter lokaler Peer-Suche:
ORACLE_TEST_DISCOVERY=local-test node tests/integration.mjs
```

Der Test erzeugt zwei eigene Identitaeten, startet beide Nodes, prueft die
gegenseitige Peer-Erkennung und notarisierte Internet-API-Abfragen in **beiden
Richtungen**. B wird dazwischen neu gestartet. Danach werden beide Nodes
beendet und ihre Belege erneut geprueft. Negative Tests pruefen falsche
Node-/Peer-IDs, eine veraenderte Node-Quittung und Kursmanipulation direkt in
der TLSNotary-Presentation. Ausserdem werden Job-Bindung, einmalige Annahme,
Replay-Abwehr und abgelaufene echte Belege geprueft. Testports: 19443/20443 und interne Ports
19047-19049/20047-20049. Die Ports muessen frei sein.
Der Discovery-Test verwendet drei Nodes auf 26443/27443/28443 und internen
Ports 26047-26049/27047-27049/28047-28049. B und C kennen nur A als Bootstrap
und finden einander ohne gegenseitige Eintraege. Negative Tests pruefen
fehlende Notarberechtigung, signierte Adressumleitung und private Ziele.

Ergebnisse unter `tests/results/run-.../report.json`; `latest.txt` wird nur
nach vollstaendig erfolgreichem Test geschrieben. Alle Testdienste werden
am Ende beendet. Private Testschluessel und Secrets bleiben lokal und sind
ueber `.gitignore` von einer Veroeffentlichung ausgeschlossen.
Unter WSL fuer den Integrationstest beispielsweise
`ORACLE_TEST_RESULTS=/tmp/oracle-tests node tests/integration.mjs` verwenden.
Der Test exportiert dann oeffentliche Artefakte in den Workspace und laesst
private Schluessel und TLSNotary-Secrets im nativen Linux-Testverzeichnis.

## Grenzen des Prototyps

TLSNotary v0.1.0-alpha.14 ist Alpha-Software. Die API-Verbindung verwendet
TLS 1.2; die separate Peer-Verbindung TLS 1.3. Unterstuetzt wird aktuell nur
der getestete KuCoin-Endpunkt, keine beliebige URL.

Dieser Prototyp verwendet maximal einen Notar je API-Sitzung und einen
gleichzeitigen Notarjob je Node. Peer-Kapazitaeten, Nachrichtengroessen und
Zeitlimits sind begrenzt. Fuer oeffentlichen Dauerbetrieb fehlen unter anderem
unabhaengige Sicherheitspruefung, Last-/Langzeittests, automatische Sperrung
kompromittierter Identitaeten, Netzwerk-Governance und Sybil-Schutz. Seed-Vertrauen ist die bewusste
Vertrauensregel dieses Tests. Entdeckung allein beweist keine Unabhaengigkeit.

Ein Pruefer muss dem Notar vertrauen, dass er nicht mit dem Abfrager kolludiert.
Lokale getrennte Prozesse beweisen keine unabhaengigen Betreiber. Der Beleg
beweist nicht die sachliche Wahrheit eines API-Wertes. Die signierte
Erfassungszeit ist kein unabhaengiger Zeitstempel. Die Job-Zeitfenster setzen
eine vertrauenswuerdige Prueferuhr voraus. Die lokale Zufallsauswahl wird
persistiert, ist aber kein extern nachpruefbarer Zufallsentscheid. Betreiber
koennen ihre eigene Software und Zulassungen veraendern. Die dauerhafte Queue
nimmt Einzeljobs und begrenzte Intervallserien an; unbegrenzte Dauerabos
und eine netzwerkweite Annahmeliste sind noch nicht implementiert.

Die mitgelieferten TLSNotary-Cargo-Manifeste deklarieren MIT/Apache-2.0.
Vor einer Veroeffentlichung sind die Lizenzhinweise aller Abhaengigkeiten zu
pruefen und zu uebernehmen.

TLSNotary: https://tlsnotary.org/docs/intro/

## Optionaler Latenzversuch

Der separat zu startende [Subsekunden-Benchmark](experiments/subsecond/README.md)
untersucht vorbereitete, einmal verwendete MPC-TLS-Sitzungen. Er aendert weder
die Node-Installation noch den laufenden Dienst. Unter einer Sekunde wurde
bisher nur im lokalen Kryptografie-Test fuer vorher bekannte Jobs beobachtet;
eine solche Antwortzeit fuer beliebige Internet-Jobs ist nicht nachgewiesen.
