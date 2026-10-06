# Sicherheitsmodell und Betrieb

Dies ist ein experimenteller Prototyp, kein auditierter produktionsreifer
Oracle-Dienst. TLSNotary v0.1.0-alpha.14 ist eine Alpha-Abhaengigkeit. Die
Haertung betrifft Protokollgrenzen, Prozesslebensdauer und Betrieb; sie
ersetzt keine kryptografische oder unabhaengige Sicherheitspruefung.

## Was ein Beleg bedeutet

Ein akzeptierter TLSNotary-Beleg authentifiziert Server und offengelegte
Anfrage-/Antwortbytes unter der Annahme, dass der akzeptierte Notar nicht
mit dem Abfrager kolludiert. Die Node-Signatur authentifiziert den
Aussteller und seine Job-Zuordnung. Signaturen beweisen nicht die
sachliche Wahrheit des API-Wertes oder die Unabhaengigkeit der Betreiber.

Eine lokale Zufallsauswahl aus ausdruecklich zugelassenen Zeugen ist keine
offene, Sybil-resistente Zeugenwahl. Unterschiedliche Schluessel oder
Container auf demselben Rechner schaffen keine unabhaengigen Betreiber.
Den erwarteten Node-/Notarschluessel ausserhalb des eingereichten Belegs
authentisch beziehen. Neu entdeckte Peers sind keine automatisch
vertrauenswuerdigen Zeugen.
Die lokale Wahl wird vor Kontakt fuer die Job-Ausfuehrung persistiert; bei
Ausfall des bestimmten Zeugen wird kein Ersatz neu ausgewaehlt. Das schuetzt
einen ehrlich betriebenen Dienst gegen unbeabsichtigtes Neuwuerfeln. Ein
boesartiger Betreiber kann seine lokale Software, Zulassungen und Listen
veraendern; die Wahl ist keine extern nachpruefbare Netzwerk-Lotterie.

## Betriebsgrenzen

### Discovery ist keine Zeugen-Zulassung

Ausgehend verbundene Clients koennen mit `--outbound-only true` teilnehmen,
ohne eine Adresse zu veroeffentlichen. Ihr signierter Descriptor muss
`outboundOnly: true` und `address: null` enthalten. Sie werden nicht in
dialbaren Peer-Antworten verteilt und nicht als Rueckverbindungsziel benutzt.
Die Identitaetspruefung und Ressourcenlimits gelten weiterhin. Der Modus
eroeffnet keine Notarsitzung und erteilt keine Zeugenberechtigung.
Eine ausdrueckliche `allow-client`-Freigabe erlaubt einem bekannten
Outbound-Client eingehende Jobreservierungen und Sitzungskanaele. Seine
TLS-Identitaet und sein signierter adressloser Descriptor muessen zum
gespeicherten Client-Pin passen. Die maximal 32 Freigaben sind getrennt
von Notar-Seeds; `remove-client` plus Dienstneustart widerruft sie.

`closed` ist der Standard fuer einen vorab zugelassenen Teilnehmerkreis.
`public` ermoeglicht Discovery neuer Peers ueber global routbare IP-Adressen;
`local-test` dient ausschliesslich numerischen Loopback-Adressen. Einen
bekannten Bootstrap mit authentisch bezogener 64-Hex-Node-ID konfigurieren.
Bootstrap-Pins werden mit `add-bootstrap` verwaltet und sind von den
TLSNotary-Zulassungen durch `add-seed` getrennt.

Im offenen Modus sind Discovery-Hellos neuer Teilnehmer moeglich. Deren
Zertifikatsidentitaet muss zur signierten Beschreibung passen. Die
Operationen `reserve`, `channel` und `release` bleiben Seeds mit exakter
konfigurierter ID/Adresse vorbehalten. API-Jobs verwenden weiterhin nur
zugelassene Seeds; Discovery allein begruendet kein Notarvertrauen.

Fuer oeffentliche Discovery prueft die Node aufgeloeste Ziel-IP-Adressen
vor dem Verbindungsaufbau und verbindet sich mit der geprueften IP, statt
beim Dial erneut unkontrolliert DNS aufzulosen. Private, reservierte und
Loopback-Ziele sind dort ausgeschlossen. Diese Regeln ersetzen keine
Firewall oder Egress-Policy fuer einen oeffentlichen Linux-Host.

Die Peer-Liste ist auf 64 Teilnehmer, darunter maximal 32 nicht vorab konfigurierte
Peers, begrenzt. Maximal acht Discovery-Bootstraps und begrenzte
Wiederverbindungen schuetzen Ressourcen, garantieren aber keine
Verfuegbarkeit bei boesartigen Teilnehmern. Sybil-/Eclipse-Angriffe und
Kollusion werden durch Discovery oder signierte Beschreibungen nicht
grundsaetzlich geloest. Einen Bootstrap als Einstiegspunkt zu nutzen ist
keine Garantie fuer vollstaendige oder neutrale Peer-Informationen.

Das Repository bleibt privat. Der Kasvio-Testserver ist ein gezielt
eingerichteter Einstiegspunkt, kein automatisch vertrautes offenes
Bootstrap-Netz. Fuer Internetbetrieb braucht jede
erreichbare Node eine routbare beworbene Adresse und zugaenglichen Port.
NAT-Traversal, automatische Portweiterleitung und Relays fehlen. Nach
Aenderung des Discovery-Modus oder der Bootstrap-Konfiguration neu starten.

### Prozess und Daten

Peer-Jobs benoetigen eine laufende Node. Der lokale CLI-Broker lauscht nur
auf Loopback (`notaryPort + 3`) und prueft die eigene TLS-Identitaet.
Er ist kein oeffentlicher Steuerungsport. Die dauerhaften mTLS-Mesh-Links
erlauben beidseitige Streams ueber eine ausgehende Verbindung; sie ersetzen
keine Egress-Firewall oder allgemeine NAT-/Relay-Infrastruktur.

`trust-peer` laesst einen bereits authentifizierten bekannten Peer
ausdruecklich als Notar zu. Das kann auch eine Node ohne beworbene Adresse
sein; dann ist der Mesh-Link erforderlich. Peer-Discovery macht diese
Vertrauensentscheidung nicht selbst. Zugelassene Seeds und Client-IDs
duerfen Jobs einreichen; der Status und Ergebnisdownload werden an die
urspruengliche authentifizierte Auftraggeberidentitaet gebunden.

`submit` persistiert den erwarteten Job lokal; `job-result` prueft Beleg,
Worker und Notar gegen diese lokale Vorgabe und die Identitaetspins.
Den lokalen `submitted-jobs/`-Zustand und die Annahmeliste vor Aenderung und
Verlust schuetzen. Ein erneuter Submit derselben Ausfuehrung ist idempotent;
eine erneute Live-Annahme desselben Belegs ist nicht erlaubt.

Die dauerhafte Queue ist auf 1000 Datensaetze und 32 aktive/wartende Jobs
begrenzt und fuehrt Jobs seriell aus. Laufende Jobs werden nach einem
unklaren Neustart fehlgeschlagen markiert und nicht automatisch wiederholt.
Ein Queue-Owner-Marker bleibt nach hartem Absturz bestehen. `queue-recover`
verlangt die genaue alte Prozess-ID und verweigert Recovery fuer einen
noch existierenden Prozess; PID-Wiederverwendung fuehrt zum sicheren
Abbruch und braucht manuelle Untersuchung. Keine automatischen
Marker-Loeschungen aufgrund von Alter oder Zeitstempeln.

Intervallserien werden als begrenzter persistenter Batch angenommen und
verwenden dieselbe Auftraggeber-Zugriffskontrolle wie Einzeljobs. Maximal
32 Ausfuehrungen, mindestens zehn Sekunden Intervall und eine letzte
Startzeit hoechstens zehn Minuten in der Zukunft begrenzen den Auftrag.
Jede Ausfuehrung bindet ihren eigenen Job-Hash mit eigener Challenge an die
authentifizierte API-Anfrage. Weitere Challenges werden aus der Basisnonce
und der Ausfuehrungsnummer abgeleitet; derselbe Basisauftrag erzeugt beim
Retry dieselben Bindungen, statt neue Ausfuehrungen oder Nonces zu erzeugen.
Belege werden einzeln verifiziert und
angenommen; ein gueltiger Beleg ersetzt keine spaetere Ausfuehrung. Die
Node garantiert keine exakten Startzeiten unter Last und kein Dauerabo.

- Nur den Peer-Port oeffentlich erreichbar machen. Die drei Rust-Ports und
  der lokale CLI-Broker
  bleiben auf Loopback. Kein direkter Notardienst fuer unbekannte Clients.
- Privaten Node-/Notarschluessel und TLS-Schluessel nur im privaten
  Datenverzeichnis speichern. Unter Linux Modus 0700 fuer Verzeichnisse,
  0600 fuer private Dateien und umask 0077 verwenden. Nicht ins Repository
  oder in gemeinsam lesbare Backups kopieren.
- `kucoin.secrets.tlsn` enthaelt Offenlegungsdaten. Fuer die aktuelle
  oeffentliche API wird der vollstaendige Transcript offengelegt; diese
  Anwendung schuetzt keine API-Zugangsdaten oder vertraulichen Antworten.
- Anwendung als eigener unprivilegierter Benutzer betreiben; Programm und
  `bin/` im Dienstbetrieb nur durch den Administrator schreibbar machen.
  Unvertrauenswuerdige Engine-Verzeichnisse und Runtime-Umgebungsvariablen
  koennen beliebigen Code ausfuehren. Der Launcher bereinigt geerbte
  Umgebungsvariablen; das systemd-Beispiel verwendet feste absolute Pfade.
- Systemd-Beispiel begrenzt Speicher, Tasks, offene Dateien und CPU. Die
  Werte sind Startwerte, keine zugesicherte Kapazitaet. OOM oder Limits
  duerfen einen Job fehlschlagen lassen; kein Ergebnis als Erfolg melden.
- Job-/Log-Verzeichnisse ueberwachen und eine externe Disk-Quota einsetzen.
  Eine Aufbewahrungsregel muss verifizierbare Belege erhalten und private
  Daten bewusst behandeln; niemals ungeprueft aktive Jobdaten loeschen.
- Die API ist fest auf den getesteten KuCoin-Endpunkt begrenzt. Arbitrary-
  URL-Support benoetigt gesonderte SSRF-/DNS-/Redirect-Regeln und Tests.

## Installation und Updates

`install.sh` baut mit `cargo build --locked` lokal. Es installiert keine
Systempakete, keinen Dienst und keine Firewallregeln. Bereits vorhandene
Binaries werden nur mit `--replace-binaries` ersetzt. Vor einem Update den
Dienst stoppen; alle vier Binaries gemeinsam auf denselben Stand bringen.
Ein Abbruch beim Kopieren kann verschiedene Staende hinterlassen. Dann
Installation erneut abschliessen, bevor der Dienst gestartet wird.

Ein Lockfile fixiert Abhaengigkeiten, authentifiziert aber nicht den
Herausgeber des Downloads. Das Repository ist privat; ein signiertes
Release-Verfahren existiert noch nicht. Vor oeffentlicher Verteilung muessen
Release-Authentizitaet, Lizenzhinweise, reproduzierbare Build-/CI-Pruefungen
und ein Sicherheitskontakt festgelegt werden. Kein `curl | bash` verwenden.
Bekannten Quellstand pruefen, bauen, lokal testen und erst dann ausrollen.

Private Identitaeten beim Update bewahren. Bei Kompromittierung ist ein
authentischer ausserbandlicher Austausch der vertrauten IDs erforderlich.
Zertifikatserneuerung unter derselben Identitaet und manuelles Entfernen
eines Seeds sind moeglich; danach den Dienst neu starten. Automatische
Identitaetsrotation, netzwerkweiter Widerruf und Governance fehlen weiterhin.

## Verbleibende Pruefungen

Lokale Integrationstests belegen keine unabhaengigen Betreiber und keine
Internet-/NAT-Verfuegbarkeit. Oeffentlicher Betrieb braucht zusaetzlich
Protokoll-Fuzzing, Langzeittests, unabhaengige Codepruefung, realistische
Angreifer-/Kollusionsmodelle und betriebliche Alarmierung. Job-Aktualitaet
setzt eine passende Verifikationsregel und vertrauenswuerdige Uhr voraus;
eine signierte lokale Uhrzeit ist kein unabhaengiger Zeitstempel.

Die zusaetzlichen Live-Tests zwischen Kasvio-Server und lokaler
Outbound-Node bestaetigen Internet-Verbindung, Rueckkanal-Notararbeit und
delegierte Peerjobs fuer diese konkrete Konfiguration. Beide Systeme
werden vom selben Betreiber kontrolliert. Die Tests sind daher kein
Beleg fuer unabhaengige Zeugen, Kollusionsresistenz, beliebige NAT-Umgebungen
oder dauerhafte Verfuegbarkeit.
# Zusaetzliche Grenzen der Mesh-Integration

Neben den Grenzen je Verbindung werden hoechstens 128 eingehende
virtuelle Streams gleichzeitig bearbeitet. Ausgehende TLS-Verbindungen
werden auch nach DNS-Aufloesung erneut gegen die Grenze von 32 geprueft.
Veraltete unbekannte Peers verlieren ihren offenen Link beim Entfernen
aus der Peer-Liste. Die lokale Vermittlung lauscht nur auf Loopback und
verlangt den eigenen Node-Schluessel. Startfehler schliessen bestehende
Sockets und native Prozesse; die Queue wird erst nach erfolgreichem
Start beider Listener geoeffnet.
