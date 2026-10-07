# Sicherheitsmodell des Oracle-Prototyps

Dieser Prototyp hat konkrete Schutzmaßnahmen und reproduzierbare Negativtests.
Eine Garantie absoluter Sicherheit, unabhängiger Betreiber oder unbegrenzter
Skalierbarkeit lässt sich daraus nicht ableiten. TLSNotary ist hier eine
experimentelle Abhängigkeit; Produktionsbetrieb mit wertvollen Jobs benötigt
zusätzlich unabhängiges Audit, Lasttests und eine Betreiberpolitik.

## Drei unterschiedliche Berechtigungen

1. **Discovery/Transport:** Ein Peer weist mit TLS und signiertem Descriptor nach,
   dass er seine Node-ID kontrolliert. Dies gestattet die verschlüsselte
   Kommunikation und Peer-Suche. Es beweist weder Ehrlichkeit noch einen eigenen
   unabhängigen Betreiber.
2. **Notardienst benutzen:** Das öffentliche Profil kann authentifizierten
   Teilnehmern begrenzte Notarsitzungen erlauben. Ein Kunde muss dafür kein
   vertrauenswürdiger Zeuge sein. Ein fremder Kunde erhält keine Rechte, Ergebnisse
   anderer Kunden abzurufen oder Zeugen zuzulassen.
3. **Als Zeuge anerkannt werden:** Ein Prüfer benötigt einen unabhängig gesetzten
   Node-ID-/Notarschlüssel-Pin. Gossip, Erreichbarkeit und Zufall sind keine
   Zulassungskriterien. Die mitgelieferte Zeugenliste enthält einen bekannten,
   ausdrücklich zugelassenen Bootstrap-Zeugen. Das ist eine konkrete
   Vertrauensentscheidung gegenüber dessen Betreiber.

Neue öffentliche Installationen können das Profil `witnessTrust: "bundled"`
verwenden. Bestehende Konfigurationen ohne dieses Feld erhalten dadurch keine
neue Vertrauensbeziehung. `witnessTrust: "pinned"` verwendet nur eigene Pins.
`publicNotary: true` erlaubt Notarkunden nur im öffentlichen Discovery-Modus;
ohne dieses Feld bleibt die bisherige explizite Kundenzulassung erhalten.
`publicJobs: true` erlaubt außerdem einzelnen authentifizierten Kunden einzelne
Jobs sowie deren eigenen Status und Ergebnis abzurufen. Das ersetzt kein
Notarvertrauen; der heruntergeladene Herkunftsbeleg muss weiterhin einen separat
zugelassenen Zeugen verwenden. Öffentliche Intervallserien sind nicht erlaubt.
Globale Begrenzung (vier neue öffentliche Jobs pro Minute) und Begrenzung je
Identität (zwei pro Minute) begrenzen den Aufwand, verhindern aber nicht, dass
ein Angreifer die zulässige Kapazität dauerhaft beansprucht. Vor wirtschaftlich
relevantem Betrieb sind Gebühren, Priorisierung oder reservierte Kapazitäten
und eine überprüfbare Zulassungsregel nötig.

## Erweiterbare Zeugenpolitik

Das Modul `witness-policy.mjs` unterstützt optional eine durch mehrere bekannte
Ed25519-Schlüssel signierte Zeugenliste. Die **lokale** Konfiguration enthält
`witnessPolicy: { authorities: ["PEM...", "PEM..."], threshold: 2 }`.
Die Autoritäten werden niemals aus der heruntergeladenen Liste übernommen.
Ihre öffentlichen Schlüssel müssen über einen unabhängig geprüften Weg
verteilt werden. Es werden keine privaten Autoritätsschlüssel mitgeliefert.

Die Datei `node-data/witness-policy.json` enthält `payload` (Base64 des
kanonischen JSON-Dokuments) und `signatures` (Liste von `keyId` und
Base64-`signature`). Das Dokument verwendet dieses Schema:

```json
{
  "version": 1,
  "network": "oracle-node-v1",
  "sequence": 1,
  "issuedAt": 1760000000000,
  "expiresAt": 1760003600000,
  "witnesses": [{ "id": "64 hex characters", "notaryPublicKey": "compressed secp256k1 public key" }],
  "revoked": []
}
```

`normalizeWitnessPolicy()` liefert die kanonische Feldreihenfolge;
`witnessPolicySignature()` signiert die domänenseparierte Nachricht mit einem
extern verwalteten Autoritätsschlüssel. Jedes neue Dokument erhöht `sequence`.
Die maximale Gültigkeit beträgt 31 Tage. Mehrere Kopien derselben Signatur
zählen nur einmal. Der lokale Zustand verhindert Rücksprünge und unterschiedliche
Listen unter derselben Sequenz. Eine aktuelle Sperre entfernt den Zeugen auch
aus mitgelieferten und manuell eingetragenen Pins. Ein abgelaufenes, fehlendes,
manipuliertes oder unzureichend signiertes Dokument führt zur Ablehnung.

Die Laufzeit muss `loadWitnessPolicy()` vor Ausführungen und sicherheitsrelevanten
Operationen aufrufen; ein einmaliges Laden beim Start genügt für Sperrung und
Ablauf nicht. Der lokale Zeitgeber und Anti-Rollback-Zustand sind Teil der
Vertrauensbasis. Wer diesen Rechner kontrolliert oder den Zustand löscht, kann
seine eigene Zulassungsentscheidung verändern. Die Zeugenliste beschränkt sich
auf Identitäten und Schlüssel; sie erteilt keine Berechtigung, private IP-Adressen
anzusprechen, und liefert keine unkontrollierten Dial-Adressen.

Dies ist eine **Föderation** mit mehreren möglichen Zulassungsbetreibern. Eine
offene, Sybil-resistente Zulassung ohne bekannte Autoritäten benötigt einen
zusätzlichen Mechanismus, etwa eine verbindlich überprüfbare Registrierung und
ökonomische Sicherheiten. Dafür ist bisher kein Konsensmechanismus implementiert.

## Was Herkunftsbelege aussagen

TLSNotary bindet offengelegte Anfrage und Antwort an eine authentifizierte
TLS-Sitzung und die Attestierung des gewählten Zeugen. Node-Signaturen binden
den Beleg zusätzlich an Job und ausführende Node. Ein Prüfer kontrolliert
insbesondere den erwarteten Server, Pfad, Job-Hash, Ausführungszeitraum und die
Interpretation des Ergebnisses. Eine API-Antwort kann selbst falsch oder veraltet
sein; TLSNotary garantiert keine wirtschaftliche Richtigkeit des API-Anbieters.

Der Herkunftsnachweis setzt voraus, dass Abfrager und akzeptierter Notar nicht
zusammenarbeiten, um zu betrügen. Zwei Instanzen auf demselben Rechner erfüllen
keine Betreiberunabhängigkeit. Lokale Zufallsauswahl und persistierte Auswahl
verhindern versehentliches erneutes Würfeln, aber keine Manipulation durch den
Besitzer des Rechners. Eine netzwerkweit überprüfbare Zufallswahl ist noch nicht
implementiert. Mehrere freie Node-IDs beweisen keine mehreren Betreiber.

## Netz und Betrieb

Öffentliche Discovery darf nur überprüfte öffentliche numerische Zieladressen
verwenden. DNS-Antworten werden vor dem Verbinden geprüft und anschließend
numerisch verwendet. Private Adressen, Metadatendienste und unerlaubte
IPv6-Bereiche bleiben gesperrt. Testbetrieb auf Loopback ist ein eigener Modus.
Ein Relay muss Endpunkte Ende-zu-Ende authentifizieren; der Vermittler darf
keine privaten Zieladressen oder beliebigen TCP-Dienste öffnen.

Peer-, Handshake-, Sitzungs-, Stream-, Nachrichten-, Zeit- und Byte-Limits
begrenzen Ressourcen. Globale Grenzen sind zusätzlich zu Grenzen pro Node-ID
erforderlich: Ein Angreifer kann viele Schlüssel erstellen. Solche Grenzen
verhindern keinen kompletten Ausfall unter gezieltem Distributed Denial of
Service. Der einzelne mitgelieferte Einstiegspunkt und Zeuge bleibt ein
Verfügbarkeitsrisiko; mehrere unabhängig betriebene und zugelassene Instanzen
sind für den nächsten Betriebsschritt nötig.

API-Jobs dürfen keine Shell-Kommandos ausführen. Neue API-Ursprünge sollten
explizit auf einem Betreiber-Allowlist stehen. Private Netzwerke, Redirects,
beliebige Anmeldeinformationen und dynamische Protokollwechsel gehören nicht
zu einem sicheren allgemeinen Jobformat. Antwortgrößen und Extraktionspfade
müssen begrenzt sein. Authentifizierte Transkripte können sensible Inhalte wie
Cookies enthalten; veröffentliche nur den für die Prüfung erforderlichen Teil.

Betreibe die Node unter einem separaten Linux-Benutzer, schütze private Schlüssel
und Datenverzeichnisse und kontrolliere Änderungen vor einem Update. Keine
automatische Übernahme ungeprüfter GitHub-Commits als vertrauenswürdige Releases.
Kompromittierte Identitäten erfordern Sperrung und neu verteilte Pins; eine
Zertifikatserneuerung alleine behebt keinen privaten Schlüsselverlust.

Nur der Peer-Port gehört ins öffentliche Netz. Die drei nativen TLSNotary-Ports
und der CLI-Broker bleiben auf Loopback; der Broker verlangt die eigene
Node-Identität. Private Datenverzeichnisse benötigen Linux-Modus 0700, private
Dateien 0600 und umask 0077. Programmdateien und Engine-Verzeichnisse dürfen im
Dienstbetrieb nur administrativ verändert werden. `kucoin.secrets.tlsn` und
vollständige offengelegte Transkripte enthalten keine Vertraulichkeitsgarantie.

Die Queue speichert höchstens 1000 Datensätze, davon höchstens 32 aktiv/wartend,
und führt Jobs seriell aus. Ein unklar unterbrochener Job wird nicht automatisch
wiederholt. Nach hartem Absturz bleibt ein Owner-Marker bestehen; `queue-recover`
verlangt die genaue alte Prozess-ID und verweigert die Wiederherstellung, wenn
diese noch existiert. PID-Wiederverwendung führt zum sicheren Abbruch und braucht
manuelle Untersuchung. Marker dürfen nicht automatisch aufgrund ihres Alters
gelöscht werden. Der persistierte `submitted-jobs/`-Zustand gehört zur lokalen
Erwartung beim Prüfen heruntergeladener Ergebnisse.

Intervalljobs sind begrenzte persistente Batches, kein unbeschränktes Dauerabo:
maximal 32 Ausführungen, mindestens zehn Sekunden Intervall und eine letzte
Startzeit höchstens zehn Minuten in der Zukunft. Jede Ausführung hat eine eigene
Job-Bindung. Unter Last sind exakte Startzeiten nicht garantiert. Die lokale Uhr
ist Teil der Aktualitätsprüfung und kein unabhängiger Zeitstempel.

Das systemd-Beispiel begrenzt Speicher, Prozesse, offene Dateien und CPU; die
Werte sind Startwerte, keine Kapazitätsgarantie. Zusätzlich Disk-Quota und
Aufbewahrung für Belege und Logs einrichten. Bei Ressourcenmangel dürfen Jobs
fehlschlagen; sie dürfen nicht ohne erfolgreiche Belegprüfung als Erfolg gelten.

`install.sh` baut mit `cargo build --locked`. Vor einem Binärupdate die Node
stoppen und alle vier Engine-Dateien auf denselben Stand bringen. Ein Lockfile
fixiert Abhängigkeiten, bestätigt aber nicht die Herkunft eines Downloads. Ein
abgebrochener Kopiervorgang muss vor erneutem Start abgeschlossen werden. Private
Identitäten beim Update erhalten. Signierte Releases, unabhängige Fuzzing-/Audit-
Ergebnisse und ein verbindlicher Sicherheitskontakt fehlen weiterhin.

## Reproduzierbare Prüfung

```sh
node tests/witness-policy.mjs
```

Die Policy-Tests prüfen gültige Schwellen-Signaturen, fehlende und doppelte
Signaturen, unbekannte Autoritäten, Manipulation, Ablauf, zukünftige Gültigkeit,
Rollback, Equivocation, Sperrung, Schlüsselkonflikte, kanonische Kodierung,
explizite Standardzulassung und beschränkte öffentliche Notarkundenrechte.
Netzwerk- und API-Integration müssen zusätzlich mit den separaten Tests geprüft
werden; diese Unit-Tests bestätigen keine öffentliche Erreichbarkeit oder
Betreiberunabhängigkeit.
