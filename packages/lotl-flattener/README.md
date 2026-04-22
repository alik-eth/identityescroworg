# @qkb/lotl-flattener

Offline EU trusted-list flattener for QKB. It reads the EU List of Trusted
Lists (LOTL), fetches each Member State trusted list, verifies XML signatures
when requested, filters qualified certificate issuing services for electronic
signatures, and emits the Poseidon Merkle artifacts consumed by the web app and
registry tooling.

## Live EU LOTL

The current EU LOTL distribution point is:

```sh
https://ec.europa.eu/tools/lotl/eu-lotl.xml
```

Before pinning an anchor, inspect the certificate embedded in the current LOTL
and compare its fingerprints with the Official Journal trusted-certificate
publication:

```sh
pnpm -F @qkb/lotl-flattener build
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --lotl https://ec.europa.eu/tools/lotl/eu-lotl.xml \
  --print-lotl-signers
```

The European Commission DSS diagnostic page currently exposes the live LOTL
status and the OJ trusted-certificate fingerprints at:

```sh
https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/tl-info
https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/oj-certificates
```

Production runs must pin trusted LOTL signing certificates from the Official
Journal / Commission publication channel, then require signatures:

```sh
pnpm -F @qkb/lotl-flattener build
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --lotl https://ec.europa.eu/tools/lotl/eu-lotl.xml \
  --out ./dist/eu-lotl \
  --lotl-version eu-lotl-YYYY-MM-DD \
  --trust-domain eidas-eu-lotl \
  --trust-source https://ec.europa.eu/tools/lotl/eu-lotl.xml \
  --require-signatures \
  --allow-insecure-transport \
  --lotl-trust-anchor ./fixtures/lotl-trust-anchors
```

Inspect the generated artifacts before publishing them to the web app:

```sh
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --inspect-output ./dist/eu-lotl
```

Multiple policy-approved trust-list outputs can be merged into a single
circuit-compatible Merkle root. Generate each source independently under its
own legal/signature policy, then combine the output directories:

```sh
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --combine-output ./dist/eu-lotl ./dist/ua-tl-ec \
  --out ./dist/combined-eu-ua \
  --lotl-version combined-eu-ua-YYYY-MM-DD \
  --trust-domain combined-eidas-eu-ua-tl-ec \
  --trust-source eidas-eu-lotl-YYYY-MM-DD \
  --trust-source ua-tl-ec-YYYY-MM-DD
```

The combined root is still one public `rTL` input for the circuit. The legal
policy decision is moved to root registration: only register combined roots
whose source lists and recognition basis are acceptable for the deployment.
The selected policy labels are written to `root.json` and `trusted-cas.json`;
they are metadata for audits and registry governance, not private circuit
inputs.

## Ukraine TL-EC

Ukraine's official cross-border trusted list is published at:

```sh
https://czo.gov.ua/download/tl/TL-UA-EC.xml
```

The companion SHA-256 file is:

```sh
https://czo.gov.ua/download/tl/TL-UA-EC.sha2
```

The 2026-02-26 TL-EC file used for the combined root had SHA-256:

```sh
7c1e086ebceaad78e6b7b41a8f532abdabfa8c8912c09c518ad29df06c75df5b
```

Treat this as a separate policy source (`ua-tl-ec-*`) and combine it with the
EU LOTL output only when the deployment intentionally accepts that recognition
basis.

`--lotl-trust-anchor` accepts one or more `.cer`, `.crt`, `.der`, or `.pem`
files, or directories containing those files. With `--require-signatures`, the
LOTL itself is verified against those anchors. Member State TLs are then
verified against the signing certificates carried in the authenticated LOTL
pointers.

`--allow-insecure-transport` is only accepted with `--require-signatures`.
This exists for Member State hosts with broken TLS chains; XMLDSig remains the
trust boundary.

To inspect each Member State TL without aborting on the first failing country:

```sh
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --lotl https://ec.europa.eu/tools/lotl/eu-lotl.xml \
  --require-signatures \
  --allow-insecure-transport \
  --lotl-trust-anchor ./fixtures/lotl-trust-anchors \
  --diagnose
```

For diagnostics only:

```sh
pnpm --dir packages/lotl-flattener exec node dist/index.js \
  --lotl https://ec.europa.eu/tools/lotl/eu-lotl.xml \
  --out ./dist/eu-lotl \
  --warn-unsigned
```

Do not use `--warn-unsigned` output as a production trusted root.

## Live Smoke Test

The normal test suite is offline. To exercise the live EU LOTL:

```sh
LOTL_LIVE=1 \
LOTL_ALLOW_INSECURE_TRANSPORT=1 \
LOTL_TRUST_ANCHORS=./fixtures/lotl-trust-anchors \
pnpm --dir packages/lotl-flattener exec vitest run tests/integration/live-lotl.test.ts
```

Optional overrides:

```sh
LOTL_URL=https://ec.europa.eu/tools/lotl/eu-lotl.xml
LOTL_VERSION=eu-lotl-YYYY-MM-DD
```

`LOTL_TRUST_ANCHORS` may contain multiple files/directories separated by `:`.

## Security Notes

- Holder signatures remain CAdES `.p7s`; XMLDSig is only for trusted-list
  authenticity.
- Member State `Qualifications/QualificationElement` data is parsed from the
  authenticated TL XML. The flattener keeps explicit `QCForESig` CA/QC services,
  rejects seal/legal-person-only services, and uses `CriteriaList` key usage
  (`nonRepudiation`) as the current fallback for signature-oriented services.
- The flattener parses the authenticated signed XML reference returned by
  XMLDSig verification, not the original raw document.
- The Merkle leaf remains the canonicalized CA certificate hash. Service
  metadata and service validity windows are emitted beside the leaf so current
  circuits remain compatible.
