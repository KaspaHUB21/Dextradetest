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

Eine Auswahl per Job-Hash aus ausdruecklich zugelassenen Zeugen ist keine
offene, Sybil-resistente Zeugenwahl. Unterschiedliche Schluessel oder
Container auf demselben Rechner schaffen keine unabhaengigen Betreiber.
Den erwarteten Node-/Notarschluessel ausserhalb des eingereichten Belegs
authentisch beziehen. Neu entdeckte Peers sind keine automatisch
vertrauenswuerdigen Zeugen.
Die Seed-Liste muss verbindlich vorgegeben sein. Selbst erzeugte Jobs oder
veraenderte Listen erlauben dem Betreiber Einfluss auf die Auswahl. Bei
Ausfall des bestimmten Zeugen wird kein Ersatz neu ausgewaehlt.

## Betriebsgrenzen

- Nur den Peer-Port oeffentlich erreichbar machen. Die drei Rust-Ports
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
