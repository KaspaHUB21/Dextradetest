# Abschlussbericht: Oracle-Node-Netzwerk

Stand: 7. Oktober 2026. Drei Agenten bearbeiteten Peer-Transport, API-Jobs
und Sicherheitsmodell. Die Hauptinstanz pruefte Zwischenstaende, integrierte
die Aenderungen und testete das oeffentliche Netz. Dieser Bericht beschreibt
getestete Funktionen und verbleibende Grenzen; er ist kein formales Audit.

## Ergebnis

Frische Linux-Installationen finden den bekannten Anker automatisch und lernen
darueber andere Nodes. Auch zwei Nodes ohne eigene oeffentliche Adresse koennen
sich gegenseitig authentifizieren und Jobs ueber einen Vermittler austauschen.
Ein kompletter TLSNotary-Beleg wird gegen einen separat zugelassenen Notar
geprueft, bevor ein Ergebnis angenommen wird. Ein zufaellig entdeckter Peer
wird dabei nicht ungeprueft zum vertrauenswuerdigen Notar.

Die lokale Node und der oeffentliche Bootstrap wurden aktualisiert, unter
Erhalt ihrer bisherigen Identitaeten und Notarschluessel. Die vorige Version
ist fuer Rueckkehr gesichert. Eine bereits installierte dritte Node muss
ebenfalls auf diesen Stand gebracht werden, um die neue Vermittlung und
API-Job-v2-Funktionen zu unterstuetzen; alter Quellstand aktualisiert sich
nicht automatisch. Der getestete Neuinstallationsablauf brauchte keine
manuellen Peer-Pins, Notar-Pins oder Aufruferfreigaben.

## Was funktioniert

| Bereich | Implementierung und Test |
|---|---|
| Installation | Linux-Setup, vorhandene oder lokal geladene Laufzeiten, gesperrte Rust-Abhaengigkeiten, fehlende Quelldateien werden erkannt |
| Einstieg | Domain-Anker mit fester Node-ID, automatische ausgehende Verbindung, weitere Einstiegspunkte konfigurierbar |
| Peer-Suche | Signierte Beschreibungen, begrenztes Gossip, Identitaetspruefung, Wiederverbindung und gepruefter Cache |
| Nodes hinter NAT | Vermittlung nur zwischen live verbundenen Identitaeten; inneres gegenseitiges TLS1.3, kein Zugriff des Vermittlers auf Klartext |
| Jobs | Frische Vorlage, einzelne Remote-Auftraege, dauerhafte Warteschlange, Status und kompletter Ergebnisbeleg; freigegebene Serien mit Intervall |
| APIs | KuCoin v1 erhalten; v2 oeffentliche HTTPS443-GET-JSON-Abfragen mit genauer URL und typisierter JSON-Pointer-Auswertung |
| Notarauswahl | Zufall aus erreichbaren zugelassenen Notaren, dauerhaft an den Auftrag gebunden, kein stilles erneutes Wuerfeln |
| Vertrauen | Erster Notar mit exakter Node-ID und Notarschluessel mitgeliefert; Betreiber-Pins oder zeitlich begrenzte Listen mit Signaturschwelle erweiterbar |
| Ergebnispruefung | TLS-Herkunft, exakte Anfrage und Antwort, Auftrag, Node-Signatur, Notar-ID und Notarschluessel; Werte werden aus dem authentifizierten Inhalt erneut abgeleitet |
| Missbrauchsgrenzen | Nachrichten-, Speicher-, Stream-, CPU-Protokoll- und Zeitgrenzen; Flusskontrolle; begrenzte oeffentliche Job-Annahme und Notarsitzungen |
| Widerruf | Abgelaufene, widerrufene und zurueckgesetzte Notarlisten scheitern; erneute Zulassungspruefung nach Belegerzeugung und vor Ergebnisannahme |
| Bedienung | `status` trennt beobachtete, direkt verbundene und ueber Relay erreichbare Peers sowie zugelassene Notare |

## Durchgefuehrte Pruefungen

1. **Peer-Netz:** drei direkt erreichbare und zwei ausgehende Test-Nodes
   fanden und authentifizierten einander. Private Ziele, manipulierte
   Adressbeschreibungen und unzulaessige Relay-Operationen wurden abgewiesen.
   Eine Node verband sich nach Neustart ueber ihren Cache, obwohl ihr
   Bootstrap abgeschaltet war.
2. **Vier-Node-Job:** Einstiegspunkt, ausgehender Auftraggeber, ausgehender
   Worker und ausgehender Notar. Job-Annahme, Status, Belegabruf und alle
   drei TLSNotary-Kanaele liefen ueber Relays. Echte KuCoin-Antwort geprueft;
   Wiederverwendung abgewiesen; Beleg bei abgeschalteten Nodes pruefbar.
3. **API-v2:** echte KuCoin-BTC-Abfrage und echte Coinbase-BTC-Abfrage.
   Lokale Ausfuehrungen dauerten 4.179 beziehungsweise 3.886 Sekunden.
   Falscher Endpunkt, anderer Job, veraenderter Beleg und erneute Annahme
   wurden abgewiesen. Auch ein absichtlich falscher Wert mit einer gueltigen
   Worker-Signatur wurde abgewiesen, weil er nicht zur TLS-Antwort passte.
4. **Oeffentlicher Neuinstallationstest:** zwei frische lokale Identitaeten
   mit dem echten Server unter `kasvio.network:9443`, ohne manuelle Freigaben.
   Gegenseitige Peer-Suche und Authentifizierung, Coinbase-Remote-Job,
   unabhaengige Belegpruefung, Offline-Pruefung und Replay-Abwehr bestanden.
   Gesamtzeit des Remote-Jobs mit Statusabfragen: **17.961 Sekunden**.
5. **V1-Regression:** zwei echte KAS-USDT-Abfragen mit wechselnden Rollen,
   Neustart, Offline-Pruefung, Identitaets-/Preis-/Quittungsmanipulation,
   abgelaufener Auftrag und dauerhafte Replay-Abwehr bestanden.
6. **Sicherheitsreihen:** 15 Notarlisten-Pruefungen, elf Peer-Angriffstests,
   DNS-Adress-/Parallelitaetspruefungen, API-Schema, Job-Ledger, Warteschlange,
   Mesh-Flusskontrolle und vier Dienst-Lebenszykluspruefungen bestanden.
   Native Zieladress- und Proxygrenzen wurden getestet; ein Build mit
   `tlsn_insecure` wurde gezielt durch einen Compile-Fehler abgewiesen.

Die Tests gegen echte APIs beweisen Funktion unter den getesteten Bedingungen.
Die Prozesse und Server stehen unter unserer Kontrolle; verschiedene Node-IDs
beweisen keine unabhaengigen Betreiber. Die Testberichte enthalten keine
privaten Schluessel und keine API-Cookies; volle Belege bleiben in privaten
Laufzeitverzeichnissen.

Wiederholbare Tests: `tests/public-network.mjs`, `tests/live-api-jobs.mjs`,
`tests/relay-jobs.mjs`, `tests/discovery-network.mjs`, `tests/integration.mjs`
und die weiteren Reihen unter `tests`. Die Tests brauchen gebaute Engines;
fuer Schluesseltests ein natives Linux-Dateisystem und fuer Live-Tests Internet.

## Was weiterhin fehlt

- **Keine absolute Sicherheit.** TLSNotary setzt unter anderem einen ehrlichen
  unabhaengigen Notar voraus. Absprachen zwischen Worker und Notar werden
  nicht durch eine zweite frei erzeugte Node-ID verhindert. Keine formale
  Kryptographiepruefung oder externe Sicherheitspruefung wurde durchgefuehrt.
- **Kein offenes Sybil-resistentes Notarnetz.** Der Standard vertraut einem
  bekannten Notar. Neue unabhängige Betreiber muessen per Pin oder signierter
  Liste zugelassen werden. Wirtschaftliche Eintrittsregeln, Slashing und
  dezentrale Governance sind noch nicht umgesetzt. Die Bootstrap-Rolle
  selbst gibt keine Notarrechte; die separate mitgelieferte Liste tut dies.
- **Begrenzte Skalierung.** Mehrere Einstiegspunkte und Relays koennen
  hinzukommen; es gibt keinen weltweit skalierenden DHT, adaptive
  Routingtabelle, Mehrsprung-Vermittlung oder NAT-Hole-Punching. Ein einzelner
  Anker hat endliche Peer- und Verbindungsgrenzen und kann ausgelastet werden.
  Ein gross angelegter Last- und Langzeittest steht aus.
- **Dienstverfuegbarkeit bleibt angreifbar.** Globale Quoten begrenzen
  Ressourcenverbrauch, verhindern aber nicht, dass fremde Teilnehmer die
  vorhandene Kapazitaet belegen. Automatisches Erkennen unabhaengiger Betreiber
  und wirtschaftliche Priorisierung sind nicht vorhanden.
- **Nicht unter einer Sekunde.** Der normale sichere Jobpfad erreichte das
  fruehere Latenzziel nicht. Das separat dokumentierte Vorbereitungs-Experiment
  wird dadurch nicht zur Produktionsgarantie. Auch weniger als 1MB
  Erzeugungsverkehr wurde nicht erreicht.
- **Nicht jede API.** Nur GET ohne eigene Authentifizierung/Header, Status200,
  JSON und kompatibles TLS. Rohantworten sind auf 16KiB begrenzt. POST,
  Redirects, grosse Antworten und private APIs fehlen.
- **Weitere Integrationen:** Kaspa, Covenants, Verguetung, Konsens ueber
  Ergebnisse, global nachpruefbare Notarlotterie, automatische Policy-
  Verteilung, signierte automatische Releases und Update-Rollback fehlen.

## Nutzung

Siehe [README](README.md) fuer Installation, `network-enable`, `status`,
`job-create`, `fetch` und `submit`. Vorlagen und Schema stehen unter
[templates](templates/README.md). Betreiberzulassung und private Daten
stehen im [Sicherheitsmodell](SECURITY.md); konkrete Netzgrenzen im
[Netzwerkdokument](NETWORK.md).
