# Mitgelieferte Quellen und Testschluessel

`vendor/tlsn` stammt aus dem offiziellen TLSNotary-Quellarchiv fuer
`v0.1.0-alpha.14` (https://github.com/tlsnotary/tlsn).
SHA-256 des urspruenglichen Archivs:
`fe2889ebddd8694fe5f8bfa8c761065331bae3b0ae73e36ac827a8ce71168ccb`.
Die mitgelieferten Cargo-Manifeste deklarieren MIT oder Apache-2.0.
Weitere Abhaengigkeiten und Versionen stehen in `tlsn-engine/Cargo.lock`.

Die Schluessel unter `vendor/tlsn/crates/**/test-ca` und `server-fixture`
sind bereits veroeffentlichte TLSNotary-Testfixtures. Sie sind zum Bauen
und Testen mitgeliefert und duerfen niemals als produktive Identitaeten
verwendet werden. Eigene Node-/Notarschluessel, Testlaufverzeichnisse und
TLSNotary-Secrets werden durch `.gitignore` ausgeschlossen.

Die lokalen Laufzeiten und Build-Ergebnisse sind ebenfalls ausgeschlossen.
Vor Weiterverteilung von Binaerdateien die Lizenzpflichten aller enthaltenen
Abhaengigkeiten gesondert pruefen.
