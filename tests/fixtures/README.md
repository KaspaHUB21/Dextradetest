`historical-kucoin-verified.json` is the verification output from a historical
KuCoin API test. It contains public market data and an unauthenticated public
endpoint transcript. It is used to exercise job policy parsing and time checks.
The policy test adds a synthetic job challenge; it does not create or verify a
new TLSNotary proof. Real proof verification is covered by integration tests.
