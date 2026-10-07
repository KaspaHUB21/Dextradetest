These are structural job templates, not executable fresh jobs. Replace ID, challenge
with 32 random bytes encoded in lowercase hex, and notBefore/notAfter with current
Unix milliseconds (maximum ten-minute window). Each execution needs a new challenge
and execution number. CLI `job-create --template templates/generic-api.job.json --out job.json`
creates a fresh bound job from the template API.

Version 2 supports public HTTPS on port 443, GET, HTTP status 200 and JSON only.
Use RFC 6901 JSON pointers and string, decimal (decimal string), finite number or
boolean types. Extraction is re-run from the authenticated JSON, never trusted from
the signed receipt alone. Server, exact path/query, extraction and execution window
are included in the challenge hash that is sent in the authenticated HTTP request.
Use decimal strings for monetary or high-precision values. JSON number uses JavaScript
floating-point precision; integers outside the safe integer range are rejected.

No custom authentication headers, cookies, bodies, redirects or private-network
destinations are supported. URLs/query strings are publicly disclosed in the proof;
do not include passwords/API credentials. API response including headers is disclosed
to proof recipients, so never use private/account APIs. TLSNotary supports a subset
of HTTPS servers; incompatible TLS, compression, oversized responses (>16 KiB including
headers) and malformed/non-JSON data fail safely. These templates do not establish
that every listed provider currently supports the TLSNotary client.
