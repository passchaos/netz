# Secret Discovery Service

The xDS runtime resolves `envoy.extensions.transport_sockets.tls.v3.Secret`
resources delivered over ADS. A CDS cluster whose `UpstreamTlsContext` uses
`tls_certificate_sds_secret_configs` or
`validation_context_sds_secret_config` references the secret by name instead
of embedding certificate material.

## Wire model

`grpc.xds.sds.decode` accepts the standard `Secret` message:

- `name` (field 1) must be non-empty.
- `tls_certificate` (field 2) requires `certificate_chain` and `private_key`
  data sources.
- `validation_context` (field 3) requires `trusted_ca` and accepts
  `match_subject_alt_names` exact/prefix/suffix/contains matchers with optional
  `ignore_case`. Hex SHA-256 `verify_certificate_hash` pins are checked against
  every certificate in the peer chain, and base64 SHA-256
  `verify_certificate_spki` pins are checked against every chain certificate's
  SubjectPublicKeyInfo, both after normal chain verification.
- `generic_secret` and `session_ticket_keys` are rejected.
- Only inline data sources are accepted. File, environment and watched
  directory sources belong to bootstrap certificate providers, not SDS.
- Encrypted private keys, OCSP staples, certificate timestamps, CRLs,
  custom validators, system roots and
  `allow_expired_certificate` are rejected rather than silently weakened.

The decoded secret is arena-owned and can be projected onto
`tls_material.Config` with `Secret.tlsConfig()`.

## CDS references

`cds.resource.decode` exposes `Cluster.tls_sds` only when
`Limits.allow_sds` is set. The runtime enables it; direct CDS consumers keep
the previous fail-closed behavior and must opt in. `SdsSecretConfig` names
must be non-empty, and an explicit source must be ADS. One certificate config
and one validation config are supported; repeated certificate configs, inline
material and an SDS reference for the same aspect are rejected as ambiguous.

## Controller behavior

The runtime controller derives SDS names from retained CDS resources and
subscribes to them alongside CDS/EDS. Decoded secrets are cached by name in
SotW and delta modes.

A cluster that references SDS is pending until every referenced secret is
available. Pending clusters publish no endpoints and keep fail-fast RPCs
queued. EDS payloads received while pending are retained and projected once
the secrets arrive. Resolving a secret reprojects every referencing cluster,
so rotation is atomic with the publication transaction. SotW omission or a
delta removal drops the cached secret and returns the cluster to pending
instead of publishing cleartext.

A secret of the wrong kind for a reference (for example, a validation secret
used as a certificate) is rejected on every retry until the control plane
corrects it. Delta secrets honor `Resource.ttl`: payload-free heartbeats
refresh the timer, expiry removes the cached secret and forgets its accepted
version, and the referencing cluster returns to pending.

## Verification

Native tests cover inline bytes/strings, SAN matchers, missing names and
material, unsupported sources and verification controls, byte/text/SAN limits,
CDS reference decoding and ambiguity rejection, STATIC and EDS clusters held
pending until both secrets arrive, secret removal/re-add, and delta
resolution/removal. The full-library gate runs with the rest of the suite.
