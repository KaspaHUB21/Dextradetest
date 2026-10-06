# Kasvio: eingerichtete Test-Nodes bedienen

Der Testserver und die lokale Outbound-Node sind bereits miteinander
verbunden und ausdruecklich freigegeben. Beide Systeme gehoeren demselben
Betreiber. Die Befehle unten verwenden die eingerichteten Pfade; sie sind
keine allgemeine Installationsanleitung fuer andere Rechner.

## Auf dem Server einen eigenen API-Job starten

Auf Kasvio im Terminal ausfuehren:

```bash
cd '/var/orakel node prototyp/node prototyp'
sudo -u oracle-node ./oracle-node fetch --data '/var/orakel node prototyp/node-data'
```

Der laufende Dienst `oracle-node` muss erreichbar sein, ebenso die lokale
Zeugen-Node ueber ihren bestehenden Mesh-Link. Der Befehl fragt KuCoin ab,
prueft den TLSNotary-Beleg und zeigt das Ergebnis direkt als JSON an:
`verified`, Node-ID, Zeugen-ID, `price` und den gespeicherten Job-Pfad.
Der Test verwendet KAS-USDT; der Preis wird bei jedem neuen Job neu abgefragt.

Peers und Dienststatus anzeigen:

```bash
sudo -u oracle-node ./oracle-node peers --data '/var/orakel node prototyp/node-data'
systemctl status oracle-node --no-pager
```

Eine Verbindung allein verleiht keine Zeugenberechtigung. Die lokale
Node ist in dieser Installation bereits als Zeuge freigegeben; ihre
oeffentliche Identitaet lautet
`1f9ae5fc9d56297b16e7345e2205a838fd4b33e28003ee8bff370cf800e05434`.
Der Server kann sie trotz fehlender beworbener Adresse ueber den
Rueckkanal der bestehenden Verbindung benutzen.

## Einem anderen Peer einen Job uebergeben

Die allgemeine Bedienung ist im README unter "Einen Job an einen Peer
uebergeben" beschrieben. `submit --wait true` wartet bis zum Abschluss,
laedt den Ergebnisbeleg und prueft ihn gegen den beim Submit lokal
gespeicherten Auftrag. Die Ausgabe enthaelt `verified: true` und
`accepted: true` nur nach erfolgreicher Pruefung und erstmaliger Annahme.
Ein erneutes Einreichen derselben Ausfuehrung fuehrt nicht automatisch
zu einer neuen API-Abfrage.

## Bestaetigte Internet-Tests

Am 6. Oktober 2026 wurden diese Ablaeufe erfolgreich ausgefuehrt:

- Server-`fetch` mit lokalem Notar: `0.04368` USDT, gespeicherter
  Server-Job `1791305629529-19b21f11`.
- Lokaler `submit --wait true` an den Server: `0.04362` USDT, Job-ID
  `local-15a98922f753543088c8ac5b`, lokaler importierter Beleg
  `received-1c331617f9a8e9ec-eebc7a1e`.

Die Kurse sind historische Testaufnahmen. Oeffentliche Belege werden
unter `tests/results/kasvio-peer-jobs` abgelegt. Private Schluessel und
TLSNotary-Secrets gehoeren nicht in diesen Export. Detaillierte Grenzen
stehen in SECURITY.md; diese Internet-Tests beweisen keine unabhaengigen
Betreiber oder ein offenes Sybil-sicheres Netzwerk.
