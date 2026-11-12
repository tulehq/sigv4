# sigv4

A Go library that verifies AWS Signature Version 4 on incoming requests, for
the Tule services that stand in for AWS ones:
[object-store](https://github.com/tulehq/object-store) (S3),
[secret-store](https://github.com/tulehq/secret-store) (Secrets Manager) and
accounts (Organizations).

It checks the signature in the `Authorization` header and, when enabled, in
presigned URLs, against signing keys from a `KeySource`. It returns its own
typed error, a `Kind` and a message, so each service answers in its own
protocol. It depends on the standard library only; the tests use the AWS SDK's
signer.

It verifies the request-level signature. It does not verify the per-chunk
signatures of `aws-chunked` (`STREAMING-*`) bodies, trailing checksums, or
SigV4A.

## Installing

```sh
go get tule.dev/sigv4
```

Go 1.27.4 or later.

## Usage

`New` takes a `KeySource` and options, and `Verify` checks one request. On
success, `Verify` replaces `r.Body` with what the handler should read: the
buffered bytes the signature covered, or, with a streamed payload, a reader
that checks the body against its declared hash.

An AWS JSON service, such as secret-store or accounts:

```go
v, err := sigv4.New(
	sigv4.NewStaticKey(cfg.AccessKeyID, cfg.SecretAccessKey),
	sigv4.WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target"),
	sigv4.WithErrorMap(toAPIError), // func(*sigv4.Error) error
)
if err != nil {
	return err
}

// In the middleware:
if err := v.Verify(r); err != nil {
	api.WriteHTTPError(w, r, err)
	return
}
```

S3, as object-store verifies:

```go
v, err := sigv4.New(
	sigv4.NewStaticKey(cfg.AccessKeyID, cfg.SecretAccessKey),
	sigv4.WithPresignedURLs(true),
	sigv4.WithStreamedPayload(),
	sigv4.WithAnyPayloadHash(true),
	sigv4.WithRequiredSignedHeaders(),
	sigv4.WithErrorMap(toS3Error),
)
```

With a streamed payload, a body that does not match its declared hash fails
the handler's read at EOF, not `Verify`, so an upload reading it is not
committed. `WithErrorMap` applies to that read too, so the handler gets the
service's own error. `example_test.go` has both setups as compiled examples.

## Options and defaults

| Option | Default | Effect |
|---|---|---|
| `WithPresignedURLs(bool)` | off | Accept the `X-Amz-*` query parameters of a presigned URL in place of the header. Off, they are plain query parameters. |
| `WithBufferedPayload(max)` | on, `DefaultMaxBodySize` (1 MiB) | Read the body up to `max` bytes and hash it. An absent `X-Amz-Content-Sha256` signs the body's own hash, as the SDKs sign AWS JSON calls; a hex one must match the body. |
| `WithStreamedPayload()` | off | Leave the body to the handler. `X-Amz-Content-Sha256` is required on a header request and defaults to `UNSIGNED-PAYLOAD` on a presigned one; a hex value is checked as the body is read. |
| `WithUnsignedPayload(bool)` | off | Accept `UNSIGNED-PAYLOAD`. |
| `WithStreamingPayload(bool)` | off | Accept `STREAMING-*`. |
| `WithAnyPayloadHash(bool)` | off | Accept any non-hex `X-Amz-Content-Sha256`, signed as sent. object-store accepts any value today. |
| `WithRequiredSignedHeaders(names...)` | `host`, `x-amz-date` | Headers the signature must cover, checked in order. None means none. A presigned URL signs `X-Amz-Date` in its query, so `x-amz-date` is not required of one. |
| `WithService(name)` | any | The service the credential must be scoped to. No Tule service checks this today. |
| `WithMaxClockSkew(d)` | `DefaultMaxClockSkew` (15m) | How far `X-Amz-Date` may be from the clock on a header request. |
| `WithMaxPresignExpiry(d)` | `DefaultMaxPresignExpiry` (7 days) | The longest `X-Amz-Expires`, in whole seconds. |
| `WithErrorMap(f)` | none | Pass every failure through `f`, from `Verify` and from a streamed body's read. Without it they return the `*sigv4.Error`. |
| `WithClock(now)` | `time.Now` | The clock request times are checked against. |

`New` fails on a nil `KeySource`, a non-positive body limit, a negative skew or
an expiry that is not a whole number of seconds.

## Errors

A failure is a `*sigv4.Error`:

```go
type Error struct {
	Err       error  // the underlying error, for KindKeyLookupFailed and KindBodyUnreadable
	Message   string // the text the Tule services send for it today
	Header    string // the header the signature had to cover, for KindUnsignedHeader
	Kind      Kind
	Presigned bool   // the request was a presigned URL
}
```

The table lists every error the services' verifiers return, and what each
service answers with. A service uses `Message` as is unless the table says
otherwise; four conditions are phrased differently in S3, and object-store
substitutes its own text for those. `Presigned` picks between the S3 header
and query error codes.

| Kind | Condition | object-store (S3) | secret-store, accounts (AWS JSON) |
|---|---|---|---|
| `KindMissingAuth` | No `Authorization` header (and no presigned URL, when accepted) | 403 `AccessDenied` "Access Denied" | 403 `MissingAuthenticationTokenException` |
| `KindUnsupportedAlgorithm` | Not `AWS4-HMAC-SHA256` | header: 400 `InvalidRequest`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindIncompleteAuth` | Header lacks `Credential`, `SignedHeaders` or `Signature`; presigned URL lacks an `X-Amz-*` parameter | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindInvalidDate` | `X-Amz-Date` missing or malformed | header: 403 `AccessDenied`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindRequestTimeTooSkewed` | `X-Amz-Date` beyond the skew | 403 `RequestTimeTooSkewed` "The difference between the request time and the current time is too large." | 403 `InvalidSignatureException` |
| `KindInvalidExpires` | `X-Amz-Expires` not 0 to the maximum | 400 `AuthorizationQueryParametersError` | (presigned URLs off) |
| `KindExpired` | Presigned URL past its expiry | 403 `AccessDenied` | (presigned URLs off) |
| `KindMissingPayloadHash` | Streamed payload, header request without `X-Amz-Content-Sha256` | 400 `InvalidRequest` | (buffered payload) |
| `KindUnsignedHeader` | A required header is not signed | (none required) | 403 `IncompleteSignatureException` |
| `KindMalformedCredential` | Credential not `<key>/<date>/<region>/<service>/aws4_request` | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindUnknownAccessKey` | The `KeySource` does not know the access key ID | 403 `InvalidAccessKeyId` "The AWS Access Key Id you provided does not exist in our records." | 403 `UnrecognizedClientException` |
| `KindCredentialDateMismatch` | Credential date is not the day of `X-Amz-Date` | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindBodyUnreadable` | Buffered payload, the body read failed | (streamed payload) | 400 `InvalidParameterException` / `InvalidInputException` |
| `KindBodyTooLarge` | Buffered payload over the limit | (streamed payload) | 413 `InvalidParameterException` / `InvalidInputException` |
| `KindPayloadHashNotAccepted` | `X-Amz-Content-Sha256` not hex and not accepted | (any accepted) | 403 `IncompleteSignatureException` |
| `KindPayloadHashMismatch` | Hex `X-Amz-Content-Sha256` does not match the body | 400 `XAmzContentSHA256Mismatch`, on the body's read | 400 `InvalidParameterException` / `InvalidInputException` |
| `KindSignatureMismatch` | The signature is wrong | 403 `SignatureDoesNotMatch` "The request signature we calculated does not match the signature you provided. Check your key and signing method." | 403 `InvalidSignatureException` |
| `KindWrongService` | Credential scoped to another service than `WithService` | (not set) | (not set) |
| `KindKeyLookupFailed` | The `KeySource` failed, or returned an empty key | (static keys) | (static keys) |

The JSON services use `InvalidParameterException` (Secrets Manager) or
`InvalidInputException` (Organizations) where the table shows both. The last
two Kinds are new: no service sets `WithService`, and `NewStaticKey` does not
fail, so neither can occur until a service opts in or plugs in another
`KeySource`. A service should answer `KindKeyLookupFailed` as an internal
error.

The checks run in the same order as the services' own verifiers did, so a
request with several faults fails on the same one: the presence of
authentication, the algorithm, the fields, the date, the skew or expiry, the
payload hash header, the signed headers, the credential's shape, its access
key, its date and service, the body, the payload hash, and last the
signature.

## Key sources

```go
type KeySource interface {
	SigningKey(ctx context.Context, scope Scope) ([]byte, error)
}

type Scope struct {
	AccessKeyID string
	Date        string // YYYYMMDD, as in the credential
	Region      string
	Service     string
}
```

A `KeySource` returns the derived signing key for a credential scope rather
than the secret it comes from, so an implementation can keep its secrets to
itself and hand out keys scoped to a day, region and service. It returns
`ErrUnknownAccessKey`, or an error wrapping it, for an access key ID it does
not know; any other error fails verification with `KindKeyLookupFailed`. The
request's context is passed through. It must be safe for concurrent use.

`NewStaticKey(accessKeyID, secretAccessKey)` knows one access key, in any
region and for any service, which is what each Tule service accepts today.
`DeriveSigningKey(secret, date, region, service)` derives a key for an
implementation that holds secrets.

## Known behaviors kept as they were

These come from the copies this library replaces and are kept so that no
client sees a change:

- The values of signed headers are whitespace-collapsed in `r.Header` itself
  while the canonical request is built, so a handler reads them collapsed.
- A presigned URL's `X-Amz-Date` is not checked against the clock, only its
  expiry is, so a URL dated in the future is accepted.
- The credential's region and service are signed but not checked, unless
  `WithService` is set.

## Development

```sh
make fmt    # format
make lint   # golangci-lint, v2.15.0 in CI
make test   # go test -race ./...
```

## License

MIT; see [LICENSE](LICENSE).
