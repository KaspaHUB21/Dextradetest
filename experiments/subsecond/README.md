# Experiment: vorbereitete TLSNotary-Sitzung

Dieses Experiment untersucht die Zeit zwischen einem Startsignal und einem geprüften KuCoin-Ergebnis. Es verwendet weiterhin MPC-TLS, Zertifikatprüfung, einen festgelegten Notarschlüssel und die kryptografische Bindung der Anfrage an einen Job. Es aktiviert weder Proxy-TLS noch die Offenlegung des Klartexts an den Notar.

**Es ist keine fertige Lösung für beliebige Jobs unter einer Sekunde.** Die bisherigen Messungen erreichten diesen Wert nur mit einem lokalen Notar und einem bereits bekannten Job. Der öffentliche Peer benötigte rund 1,49 Sekunden. Das Ziel von weniger als 1 MB Datenverkehr ist ebenfalls nicht erreicht.

## Isoliert ausführen

Auf Linux mit den im Hauptprojekt beschriebenen Node.js- und Rust-Werkzeugen sowie GNU Coreutils (`/usr/bin/timeout`):

```sh
cd experiments/subsecond
./build.sh
node run.mjs
```

Der Build legt die experimentellen Programme in `bin` innerhalb dieses Experimentordners ab. Der Runner startet einen eigenen lokalen Notar mit einer temporären Identität und erzeugt frische Einmalsitzungen. Seine Ergebnisausgabe enthält bereinigte JSON-Metadaten, Messwerte, Hashes und Prüfergebnisse. Vollständige HTTP-Transkripte und Belege werden nicht ausgegeben: Auch eine öffentliche API kann beispielsweise Cookies in Antwortheadern setzen. Er aktiviert diese Programme nicht im normalen Installer und ändert keinen laufenden Node-Dienst. Die temporäre Testidentität darf nicht als unabhängig betriebener Netzwerkzeuge interpretiert werden.

Eine externe Zeitbegrenzung beendet den Testnotar nach spätestens 65 Sekunden auch dann, wenn der Runner hart beendet wurde. Die Vorbereitung ist ebenfalls zeitlich begrenzt; ein Fehler liefert keine erfolgreiche Jobantwort.

## Was vorbereitet wird

Der Job einschließlich seiner Kennung ist vor Beginn der Vorbereitung bekannt. MPC-Vorbereitung und Aufbau der TLS-Verbindung zur echten KuCoin-API finden vor dem Startsignal statt. **Die HTTP-Anfrage wird erst nach dem Startsignal gesendet.** Jede Abfrage verbraucht eine neue Sitzung; Sitzungsschlüssel und MPC-Material werden nicht für einen zweiten Job wiederverwendet.

Die Einstellung `NetworkSetting::Bandwidth` reduziert Kommunikationsrunden und benötigt dafür mehr Daten. Sie schaltet keine kryptografische Prüfung ab. Die kleineren Ressourcenlimits passen zur getesteten Anfrage; bei Überschreitung muss der Ablauf abbrechen.

Das historische Experiment ließ den TLS-Treiber drei Sekunden laufen und wartete anschließend zwei Sekunden auf das Startsignal. Dies war eine zeitbasierte Vorbereitung, kein kryptografischer Nachweis der Bereitschaft. Der Runner dokumentiert seinen tatsächlichen Messumfang in der JSON-Ausgabe; Vorbereitungszeit darf nicht als eingesparte Gesamtzeit dargestellt werden.

## Historische Messungen vom 6. Oktober 2026

| Aufbau | Startsignal bis Abschluss des nativen Prüfers | Gesamtdauer einschließlich Vorbereitung und Wartezeit |
|---|---:|---:|
| Lokaler Notar, Abfrage 1 | 753,36 ms | 6.387,12 ms |
| Lokaler Notar, Abfrage 2 | 655,01 ms | 6.204,36 ms |
| Öffentlicher Peer, Abfrage 1 | 1.477,79 ms | 10.448,27 ms |
| Öffentlicher Peer, Abfrage 2 | 1.496,66 ms | 10.450,57 ms |

Bei den historischen lokalen Messungen wurde der Zeitstempel vor dem anschließenden Einlesen der Ergebnisdatei und der JavaScript-Prüfung des Jobfensters genommen. Diese Prüfung war erfolgreich, ihre Laufzeit ist jedoch nicht in den lokalen Werten enthalten. Die öffentlichen Werte messen die Rückkehr des Fetch-Befehls und beinhalten dessen Prüfungen. Die Messgrenzen sind deshalb ausdrücklich getrennt dokumentiert.

Der unveränderte native Prüfer akzeptierte sechs Originalbelege und lehnte jeweils einen veränderten Kurs, einen falschen gültigen Notarschlüssel und eine falsche Job-Kennung ab. Alle 24 Funktionsprüfungen wurden unabhängig offline wiederholt und bestanden. Diese Prüfungen sind kein vollständiges Sicherheitsaudit.

Die bereinigten historischen Werte stehen in [evidence-2026-10-06.json](evidence-2026-10-06.json). Sie enthalten keine privaten Schlüssel oder lokalen Jobpfade. Neue Runner-Messungen müssen getrennt von diesen historischen Ergebnissen betrachtet werden.

## Wiederholung mit dem portablen Runner

Der veröffentlichte Runner wurde am 6. Oktober 2026 mit zwei weiteren echten KuCoin-Abfragen getestet. Die neue Messgrenze enthält zusätzlich das Einlesen des Ergebnisses und die erfolgreiche JavaScript-Prüfung des aktuellen Jobfensters:

| Lokaler Notar | Startsignal bis zum vollständig validierten Ergebnis | Gesamtdauer einschließlich Vorbereitung und Wartezeit |
|---|---:|---:|
| Abfrage 1 | 743,60 ms | 6.326,19 ms |
| Abfrage 2 | 773,35 ms | 6.309,09 ms |

Danach wurden je Abfrage das Original sowie ein veränderter Kurs, ein falscher gültiger Notarschlüssel und eine falsche Job-Kennung geprüft. Alle acht Funktionsprüfungen bestanden. Die Zeit für diese zusätzlichen Negativtests ist nicht Teil der Antwortlatenz.

Die bereinigte Evidenz enthält unter `portableRunnerRetest` die effektive Konfiguration, SHA-256-Hashes der verwendeten Programme, diese Messwerte und die Prüfergebnisse. Es wurden keine vollständigen Transkripte, Cookies, Jobpfade, Schlüsselgeheimnisse oder Belegdateien aufgenommen. Diese Wiederholung bestätigt weiterhin nur den lokalen Ablauf für einen vorher bekannten Job; die Grenzen für öffentliche Peers und neue Jobs bleiben bestehen.

## Grenzen vor einem Einsatz im Netzwerk

- Zwei Messungen pro Variante belegen keine Latenzgarantie und keine Verteilung unter Last. Eine langsame API oder ein langsamer Peer kann das Zeitlimit überschreiten. Ein Zeitlimit darf nur zu einem Fehler führen, niemals zu einem ungeprüften Erfolg.
- Die lokale Messung enthält keine Netzwerk-Jobannahme, Peer-Warteschlange oder Zufallsauswahl eines unabhängigen Zeugen.
- Ein Pool vorbereiteter Sitzungen für noch unbekannte Jobs ist nicht implementiert. Dafür müssen Bereitschaft, einmalige Zuteilung, begrenzte Lebensdauer, Ressourcenlimits und Abbruch zuverlässig geregelt werden.
- Die bestehenden Regeln prüfen die authentifizierte TLS-Sitzungszeit gegen das Jobfenster. Eine vor einem neuen Job geöffnete Sitzung kann dadurch zu Recht abgewiesen werden. Diese Regel darf nicht zur Beschleunigung gelockert werden.
- Zwei Prozesse unter demselben Betreiber belegen keine Unabhängigkeit der Zeugen. Die Zulassungsregeln des normalen Prototyps gelten weiterhin.

Die normalen Programme und Installationsvorgaben bleiben unverändert. Der nächste Schritt ist ein gesondert geprüfter Entwurf für vorbereitete Einmalsitzungen und Messungen mit zwei unabhängigen Rechnern, Last und Fehlerfällen.

## Quellen

- [TLSNotary-Protokollkonfiguration](https://tlsnotary.org/docs/protocol/configuration/)
- [TLSNotary-Benchmarks](https://tlsnotary.org/blog/2025/08/31/benchmarks/)
- Lokaler Quellcode: `vendor/tlsn/crates/core/src/config/tls_commit/mpc.rs`, `vendor/tlsn/crates/tlsn/src/mpz.rs` und `vendor/tlsn/crates/tls/client-async/src/lib.rs`.
