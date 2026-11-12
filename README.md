# sigv4

A Go library that verifies AWS Signature Version 4 on incoming requests, for
the Tule services that stand in for AWS ones:
[object-store](https://github.com/tulehq/object-store) (S3),
[secret-store](https://github.com/tulehq/secret-store) (Secrets Manager) and
accounts (Organizations).

It checks the signature in the `Authorization` header and, when enabled, in
presigned URLs, against signing keys from a `KeySource`, including the
session tokens of temporary credentials. It tells handlers who signed, and
returns its own typed error, a `Kind` and a message, so each service answers
in its own protocol. It depends on the standard library only; the tests use
the AWS SDK's signer.

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
success, `Verify` returns the request to serve in its place, whose context
carries the `Principal` that signed it:

```go
verified, err := v.Verify(r)
if err != nil {
	api.WriteHTTPError(w, r, err)
	return
}
next.ServeHTTP(w, verified)

// In a handler:
p, ok := sigv4.PrincipalFrom(r.Context()) // p.AccountID, p.ARN, p.AccessKeyID
s, ok := sigv4.ScopeFrom(r.Context())     // the verified credential scope: s.Service, s.Region, ...
```

The principal comes back on the request rather than as a separate value. A
service's middleware then changes in one line, and any handler below it can
read who signed without the service writing its own context plumbing.
`sigv4.NewContext` builds such a context for handler tests. The returned
request's body, also set on `r`, is what the handler should read: the
buffered bytes the signature covered, or, with a streamed payload, a reader
that checks the body against its declared hash.

An AWS JSON service, such as secret-store or accounts:

```go
keys, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
	AccessKeyID:     cfg.AccessKeyID,
	SecretAccessKey: cfg.SecretAccessKey,
})
if err != nil {
	return err
}
v, err := sigv4.New(
	keys,
	sigv4.WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target"),
	sigv4.WithErrorMap(toAPIError), // func(*sigv4.Error) error
)
```

S3, as object-store verifies:

```go
keys, err := sigv4.NewStaticKey(sigv4.StaticKeyConfig{
	AccessKeyID:     cfg.AccessKeyID,
	SecretAccessKey: cfg.SecretAccessKey,
})
if err != nil {
	return err
}
v, err := sigv4.New(
	keys,
	sigv4.WithPresignedURLs(true),
	sigv4.WithS3PathEncoding(),
	sigv4.WithStreamedPayload(),
	sigv4.WithAnyPayloadHash(true),
	sigv4.WithRequiredSignedHeaders(),
	sigv4.WithErrorMap(toS3Error),
)
```

With a streamed payload, the body is checked against its declared hash as
the handler reads it, and a body that does not match fails a read, not
`Verify`. What that guarantees is exact. A read error comes only once the
handler has read the whole body: `Content-Length` bytes when the length is
known, or to EOF when it is not. With a known length, the read that reaches
`Content-Length` fails on a mismatch, so a handler that reads exactly that
much (`io.ReadFull`, `io.LimitReader`, `http.MaxBytesReader`) sees it. So
does a read past `Content-Length`, and an EOF short of it. A failing read
returns no bytes, because `io.ReadFull` drops an error that comes with a
full buffer.

A handler that stops earlier never reaches the check on its reads. A
decoder does exactly that: it stops at the end of its value, so a forged
body padded to the same length decodes cleanly. `Close` then reads what the
handler left, as net/http reads an unread body: at most 256 KiB, and with a
known length nothing at all when more than that is left. It returns the
mismatch when the body it read to its end does not match, and
`KindUnverifiedPayload` when the body was not read to its end, so a large
or slow body never holds the handler past that. By then the handler has seen unverified bytes, so it
must not act on them first. **A handler must read the body to
`Content-Length` (or EOF), or use `ReadBody`, before acting on its
bytes.** `v.ReadBody(r, max)` reads the whole body, up to `max` bytes, and
returns it only once it is verified. It is meant for small control
documents such as S3 DeleteObjects and CompleteMultipartUpload. A body counts as
verified only when the signature covers it: its hash was computed from it (an
AWS JSON call that sends no `X-Amz-Content-Sha256`), or declared in hex and
matched. A body sent under an opaque hash is covered by no hash, in either
payload mode, even when the verifier accepts that hash (`UNSIGNED-PAYLOAD`,
`STREAMING-*`, or any value under `WithAnyPayloadHash`). `ReadBody` refuses
such a body with `KindUnverifiedPayload`. It also refuses a body a middleware
wrapped after `Verify` (an `http.MaxBytesReader`, say), since it can no
longer tell that body is verified. So `Verify` should sit innermost, after
any middleware that wraps the body. `ReadBody`'s own limit stands in for a
`MaxBytesReader`.

`WithErrorMap` applies to these reads, `Close` and `ReadBody` too, so the
handler gets the service's own error. `example_test.go` has both setups as
compiled examples.

## Options and defaults

| Option | Default | Effect |
|---|---|---|
| `WithPresignedURLs(bool)` | off | Accept the `X-Amz-*` query parameters of a presigned URL in place of the header. Off, they are plain query parameters. |
| `WithBufferedPayload(max)` | on, `DefaultMaxBodySize` (1 MiB) | Read the body up to `max` bytes and hash it. An absent `X-Amz-Content-Sha256` signs the body's own hash, as the SDKs sign AWS JSON calls; a hex one must match the body. |
| `WithS3PathEncoding()` | off: encoded twice | Sign the path URI-encoded once, as S3 does. Every other service encodes it twice, as SigV4 specifies and the SDK signs it. |
| `WithStreamedPayload()` | off | Leave the body to the handler. `X-Amz-Content-Sha256` is required on a header request and defaults to `UNSIGNED-PAYLOAD` on a presigned one; a hex value is checked as the body is read. |
| `WithUnsignedPayload(bool)` | off | Accept `UNSIGNED-PAYLOAD`. |
| `WithStreamingPayload(bool)` | off | Accept `STREAMING-*`. |
| `WithAnyPayloadHash(bool)` | off | Accept any non-hex `X-Amz-Content-Sha256`, signed as sent. object-store accepts any value today. |
| `WithRequiredSignedHeaders(names...)` | `host`, `x-amz-date` | Headers the signature must cover, checked in order. None means none. A presigned URL signs `X-Amz-Date` in its query, so `x-amz-date` is not required of one. |
| `WithService(name)` | any | The service the credential must be scoped to. No Tule service checks this today. |
| `WithMaxClockSkew(d)` | `DefaultMaxClockSkew` (15m) | How far `X-Amz-Date` may be from the clock on a header request, and how far ahead of it on a presigned URL. |
| `WithMaxPresignExpiry(d)` | `DefaultMaxPresignExpiry` (7 days) | The longest `X-Amz-Expires`, in whole seconds. |
| `WithErrorMap(f)` | none | Pass every failure through `f`, from `Verify` and from a streamed body's read. Without it they return the `*sigv4.Error`. |
| `WithClock(now)` | `time.Now` | The clock request times are checked against. |

`New` fails on a nil `KeySource`, a non-positive body limit, a negative skew or
an expiry that is not a whole number of seconds.

A presigned URL is valid from its `X-Amz-Date` for `X-Amz-Expires` seconds.
It is refused as not yet valid when `X-Amz-Date` is more than the skew ahead
of the clock, as S3 refuses it. A URL dated ahead within the skew is accepted,
so a client whose clock runs a little fast still gets a working seven-day
URL, and no URL stays valid for longer than the skew plus the maximum expiry
from now.

## Errors

A failure is a `*sigv4.Error`:

```go
type Error struct {
	Err       error  // the underlying error, for the KeySource and body-read Kinds
	Message   string // the text the AWS JSON services send for it
	Header    string // the header the signature had to cover, for KindUnsignedHeader
	Kind      Kind
	Presigned bool   // the request was a presigned URL
}
```

The table lists every error the verifier returns, and what each service
answers with. A service uses `Message` as is unless the table quotes another.
S3 phrases several conditions differently, and object-store substitutes its
own text for those. `Presigned` picks between the S3 header and query error
codes.

| Kind | Condition | object-store (S3) | secret-store, accounts (AWS JSON) |
|---|---|---|---|
| `KindMissingAuth` | No `Authorization` header (and no presigned URL, when accepted) | 403 `AccessDenied` "Access Denied" | 403 `MissingAuthenticationTokenException` |
| `KindUnsupportedAlgorithm` | Not `AWS4-HMAC-SHA256` | header: 400 `InvalidRequest`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindIncompleteAuth` | Header lacks `Credential`, `SignedHeaders` or `Signature`; presigned URL lacks an `X-Amz-*` parameter; `SignedHeaders` is not lowercase, sorted and unique | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindInvalidDate` | `X-Amz-Date` missing or malformed | header: 403 `AccessDenied`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindRequestTimeTooSkewed` | `X-Amz-Date` beyond the skew | 403 `RequestTimeTooSkewed` "The difference between the request time and the current time is too large." | 403 `InvalidSignatureException` |
| `KindInvalidExpires` | `X-Amz-Expires` not 1 to the maximum, "X-Amz-Expires must be a number of seconds between 1 and 604800" | 400 `AuthorizationQueryParametersError` | (presigned URLs off) |
| `KindExpired` | Presigned URL past its expiry | 403 `AccessDenied` "Request has expired" | (presigned URLs off) |
| `KindRequestNotYetValid` | Presigned URL dated beyond the skew | 403 `AccessDenied` "Request is not yet valid" (1) | (presigned URLs off) |
| `KindMissingPayloadHash` | Streamed payload, header request without `X-Amz-Content-Sha256` | 400 `InvalidRequest` | (buffered payload) |
| `KindUnsignedHeader` | A required header, or `X-Amz-Security-Token`, is not signed | 403 `AccessDenied` "There were headers present in the request which were not signed" (2) | 403 `IncompleteSignatureException` |
| `KindMalformedCredential` | Credential not `<key>/<date>/<region>/<service>/aws4_request` | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindUnknownAccessKey` | The `KeySource` does not know the access key ID, or a temporary one came without its token | 403 `InvalidAccessKeyId` "The AWS Access Key Id you provided does not exist in our records." | 403 `UnrecognizedClientException` |
| `KindInvalidSessionToken` | The `KeySource` refused the session token, the key takes none, or header and query carry different tokens | 400 `InvalidToken` "The provided token is malformed or otherwise invalid." (3) | 403 `UnrecognizedClientException` "The security token included in the request is invalid." |
| `KindExpiredSessionToken` | The `KeySource` reports the token expired | 400 `ExpiredToken` "The provided token has expired." (3) | 403 `ExpiredTokenException` "The security token included in the request is expired" (4) |
| `KindCredentialDateMismatch` | Credential date is not the day of `X-Amz-Date` | header: 400 `AuthorizationHeaderMalformed`; presigned: 400 `AuthorizationQueryParametersError` | 403 `IncompleteSignatureException` |
| `KindBodyUnreadable` | Buffered payload, the body read failed | (streamed payload) | 400 `InvalidParameterException` / `InvalidInputException` |
| `KindBodyTooLarge` | Buffered payload over the limit, or a body over `ReadBody`'s limit | 400 `MaxMessageLengthExceeded` "Your request was too big." (5), from `ReadBody` | 413 `InvalidParameterException` / `InvalidInputException` |
| `KindPayloadHashNotAccepted` | `X-Amz-Content-Sha256` not hex and not accepted | (any accepted) | 403 `IncompleteSignatureException` |
| `KindPayloadHashMismatch` | Hex `X-Amz-Content-Sha256` does not match the body, or the body is longer or shorter than `Content-Length` | 400 `XAmzContentSHA256Mismatch`, on the body's read, `Close` or `ReadBody` | 400 `InvalidParameterException` / `InvalidInputException` |
| `KindUnverifiedPayload` | `ReadBody` on a body no payload hash covers or that was wrapped after `Verify`, or `Close` with more of a streamed body unread than it reads | 400 `InvalidRequest` (6) | 400 `InvalidParameterException` / `InvalidInputException` (6) |
| `KindSignatureMismatch` | The signature is wrong | 403 `SignatureDoesNotMatch` "The request signature we calculated does not match the signature you provided. Check your key and signing method." | 403 `InvalidSignatureException` |
| `KindWrongService` | Credential scoped to another service than `WithService` | (not set) | (not set) |
| `KindKeyLookupFailed` | The `KeySource` failed otherwise, or returned an empty key or a principal with no account ID | internal error | internal error |

Where each new S3 and token response comes from:

1. The S3 error body for a presigned URL dated ahead of S3's clock, as quoted
   in an AWS troubleshooting write-up: `<Code>AccessDenied</Code>` and
   `<Message>Request is not yet valid</Message>`. The write-up shows no
   status; 403 is that of `AccessDenied` in the S3 error reference.
2. The text S3 sends with `HeadersNotSigned`, as quoted in AWS forum threads.
   The S3 SigV4 documentation says the token header must be signed.
3. The S3 error reference: `InvalidToken` and `ExpiredToken`, both 400.
4. The text the SDKs report for `ExpiredTokenException`. The common-errors
   reference gives 403 and only a paraphrase of the message.
5. The S3 error reference: `MaxMessageLengthExceeded`, 400, "Your request
   was too big.", the error for an oversized request document. `ReadBody`
   reads such documents (DeleteObjects, CompleteMultipartUpload); an object
   upload over a limit would be `EntityTooLarge`, "Your proposed upload
   exceeds the maximum allowed object size."
6. No AWS counterpart: S3 accepts unsigned payloads and so has no error for
   a body it cannot verify, and the JSON services always cover their body.
   The codes shown are the services' choice.

The JSON services use `InvalidParameterException` (Secrets Manager) or
`InvalidInputException` (Organizations) where the table shows both. The
query-protocol services (IAM, STS) answer an unknown key or an invalid token
with `InvalidClientTokenId`, "The security token included in the request is
invalid."

The checks run in the same order as the services' own verifiers did, so a
request with several faults fails on the same one: the presence of
authentication, the algorithm, the fields, the date, the skew or presign
window, the payload hash header, the signed headers and session token, the
credential's shape, its access key and token, its date and service, the
body, the payload hash, and last the signature.

## Signed headers

A `SignedHeaders` list must be as SigV4 specifies it: lowercase header names,
sorted and unique, with no spaces or empty entries. Otherwise the request
fails with `KindIncompleteAuth`. The SDK signers write it that way. Each
header is then canonicalized once, so the canonical request is no larger
than the list and the headers it names, and the required-header check
compares the names exactly as they are signed. The number of names is not
capped. Unique names already bound the work by the request's header size,
which the HTTP server bounds in turn (1 MiB by default in net/http). And S3
lets a PutObject sign more than a hundred `x-amz-meta-*` headers, within
its 8 KB of request headers. Every `x-amz-*` header the request carries must
be in the list.

## Key sources

```go
type KeySource interface {
	SigningKey(ctx context.Context, scope Scope) (Key, error)
}

type Scope struct {
	AccessKeyID  string
	SessionToken string // X-Amz-Security-Token, empty when absent
	Date         string // YYYYMMDD, as in the credential
	Region       string
	Service      string
}

type Key struct {
	Principal Principal // AccountID, ARN, AccessKeyID
	Signing   []byte    // the derived signing key
}
```

A `KeySource` returns the derived signing key for a credential scope rather
than the secret it comes from, so an implementation can keep its secrets to
itself and hand out keys scoped to a day, region and service. It also returns
the `Principal` the key belongs to. It validates the session token against
the access key ID. When it has no key it returns, or wraps:

- `ErrUnknownAccessKey` for an access key ID it does not know, and for a
  temporary key sent without its token, as AWS does;
- `ErrInvalidSessionToken` for a token that is not the key's, or for a key
  that takes no token;
- `ErrExpiredSessionToken` for an expired token.

Any other error fails verification with `KindKeyLookupFailed`. The request's
context is passed through. A `KeySource` must be safe for concurrent use.

The scope is unauthenticated when `SigningKey` is called, because the
signature is checked after it, with the key it returns. The access key ID,
`Date`, `Region`, `Service` and `SessionToken` are whatever the request
claims, and anyone can call `SigningKey` with any of them. An implementation
must not cache per scope without a bound, since every request can name a
new scope. It should not reveal more about a key or token than AWS does,
so it should answer only through the sentinels, not through timing or
other errors.

`NewStaticKey(StaticKeyConfig{...})` knows one long-term access key, in any
region and for any service, which is what each Tule service accepts today.
It returns an error when the access key ID or secret is empty.
It refuses any request that carries a session token. Its principal's
`AccountID` defaults to `DefaultAccountID` (`000000000000`), and its `ARN` to
the account's root user, `arn:aws:iam::<AccountID>:root`.
`DeriveSigningKey(secret, date, region, service)` derives a key for an
implementation that holds secrets.

## Session tokens

Temporary credentials from STS carry a session token, which the SDK signer
sends the way AWS expects. On a signed request it goes in the
`X-Amz-Security-Token` header, which it lists among the signed headers. On a
presigned URL it goes in the `X-Amz-Security-Token` query parameter, which is
part of the canonical query. The verifier takes the token from either place
and requires it to be covered by the signature. A token header outside the
signed headers fails with `KindUnsignedHeader`. A header and parameter that
disagree fail with `KindInvalidSessionToken`. The token then goes to the
`KeySource` in `Scope.SessionToken`.

## Paths

The canonical URI is the path as the client sent it. For every service but
S3 it is URI-encoded once more, `%` included, as SigV4 specifies and the SDK
signs it: `/a%20b` is signed as `/a%2520b`. With `WithS3PathEncoding`, which
an S3 service sets, the path is split on the slashes sent and each segment
decoded and re-encoded, as S3 signs it encoded once. The JSON services need
nothing: they are not S3, and the default is what their clients sign.

In both modes an encoded slash (`%2F`) stays inside its segment, so a
signature over `/bucket/a/b` never verifies `/bucket/a%2Fb`, and no
signature verifies a request whose decoded path differs from the one
signed. That holds even when the raw path is not
encoded as Go's `URL.EscapedPath` requires (`/b/a%2Fb{`): the raw path is
used whenever it decodes to `URL.Path`. A raw path that does not decode to
`URL.Path`, which only a middleware rewriting one without the other leaves,
is refused with `KindIncompleteAuth`. AWS's documentation does not say how
it treats such paths, so this takes the fail-closed choice.

## Known behaviors kept as they were

These come from the copies this library replaces and are kept so that no
client sees a change:

- The values of signed headers are whitespace-collapsed in `r.Header` itself
  while the canonical request is built, so a handler reads them collapsed.
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
