// Package sigv4 verifies AWS Signature Version 4 on incoming requests, for
// the Tule services that stand in for AWS ones.
//
// Verification is request-level: the signature over the method, path, query,
// signed headers and payload hash is checked, in the Authorization header
// and, when enabled, in presigned URLs. Signing keys come from a KeySource,
// which hands out derived keys rather than secrets and says who they belong
// to; NewStaticKey covers the one access key a service accepts today. A
// session token, X-Amz-Security-Token, must be covered by the signature and
// is passed to the KeySource to validate.
//
// The payload is handled one of two ways. Buffered, the default, reads the
// body up to a limit and hashes it, which suits the AWS JSON protocol: the
// SDKs sign the payload hash without sending it. Streamed leaves the body to
// the handler and checks a declared hex hash as the body is read, which suits
// S3 uploads. The per-chunk signatures of aws-chunked (STREAMING-*) bodies
// are not verified.
//
// A failure is an *Error: a Kind naming the condition and a message. A
// service maps it to its own wire error, with WithErrorMap so a streamed
// body's read fails with it too. On success, Verify returns the request to
// serve, whose context carries the Principal that signed it.
//
// A Principal says what may be authorized for it, as its KeySource reports:
// Root, for a principal with full access to its account, which is never
// evaluated against policies, and Policies, the identity policy documents in
// effect for it. Policies are opaque JSON for a policy evaluator; sigv4 does
// not interpret them, and Verify passes both through unchanged. A StaticKey's
// principal is Root, with no policies. A Principal also carries the values of
// the principal's condition keys, aws:PrincipalArn, aws:userid,
// aws:PrincipalType, aws:PrincipalTag, aws:PrincipalOrgID and
// aws:PrincipalOrgPaths, which Verify passes through unchanged too.
package sigv4

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	algorithm   = "AWS4-HMAC-SHA256"
	amzDateFmt  = "20060102T150405Z"
	dateFmt     = "20060102"
	scopeSuffix = "aws4_request"
	tokenHeader = "X-Amz-Security-Token" //nolint:gosec // G101: a header name, not a credential
)

// Verifier checks request signatures against the keys of a KeySource. It is
// safe for concurrent use.
type Verifier struct {
	keys           KeySource
	now            func() time.Time
	mapErr         func(*Error) error
	service        string
	required       []string
	maxBody        int64
	maxSkew        time.Duration
	maxExpiry      time.Duration
	streamed       bool
	presign        bool
	allowUnsigned  bool
	allowStreaming bool
	allowAnyHash   bool
	s3Path         bool
}

// New returns a Verifier over keys. Without options it accepts Authorization
// header requests only, buffers and hashes bodies up to DefaultMaxBodySize,
// refuses UNSIGNED-PAYLOAD and STREAMING-* payloads, requires host and
// x-amz-date to be signed, accepts any service, and allows
// DefaultMaxClockSkew. It fails when keys is nil or an option is out of
// range.
func New(keys KeySource, opts ...Option) (*Verifier, error) {
	v := &Verifier{
		keys:      keys,
		now:       time.Now,
		required:  defaultRequiredSignedHeaders,
		maxBody:   DefaultMaxBodySize,
		maxSkew:   DefaultMaxClockSkew,
		maxExpiry: DefaultMaxPresignExpiry,
	}
	for _, opt := range opts {
		opt(v)
	}
	if err := v.validate(); err != nil {
		return nil, err
	}
	return v, nil
}

// signed is what a request claims about its signature.
type signed struct {
	date          time.Time
	cred          credential
	signature     string
	payloadHash   string
	sessionToken  string
	signedHeaders []string
	key           Key
	presigned     bool
	// bodyCovered is set when the signature covers the body: its hash was
	// computed from it, or declared in hex and matched. A buffered body
	// sent under an opaque hash is not covered.
	bodyCovered bool
}

// scope returns the credential scope s was signed under, as the KeySource
// is asked for it.
func (s *signed) scope() Scope {
	return Scope{
		AccessKeyID:  s.cred.accessKeyID,
		SessionToken: s.sessionToken,
		Date:         s.cred.date,
		Region:       s.cred.region,
		Service:      s.cred.service,
	}
}

// Verify checks r's signature, returning the failure, passed through the
// WithErrorMap function when one is set.
//
// On success it returns the request to serve in r's place: r with a context
// that carries the signer's Principal, read with PrincipalFrom, and the
// credential Scope the signature was verified under, read with ScopeFrom. Its body,
// also set on r, is what the handler should read: with a buffered payload,
// the bytes the signature covered; with a streamed one and a hex payload
// hash, a reader that fails if the body does not match it.
func (v *Verifier) Verify(r *http.Request) (*http.Request, error) {
	s, e := v.verify(r)
	if e != nil {
		return nil, v.mapError(e)
	}
	ctx := NewContext(r.Context(), s.key.Principal)
	return r.WithContext(context.WithValue(ctx, scopeKey{}, s.scope())), nil
}

func (v *Verifier) verify(r *http.Request) (*signed, *Error) {
	s, err := v.parse(r)
	if err != nil {
		return nil, err
	}

	var body []byte
	if v.streamed {
		if !isHexSHA256(s.payloadHash) {
			if err = v.checkOpaqueHash(s); err != nil {
				return nil, err
			}
		}
	} else if body, err = v.bufferPayload(r, s); err != nil {
		return nil, err
	}

	uri, ok := canonicalURI(r.URL, v.s3Path)
	if !ok {
		return nil, newError(KindIncompleteAuth, s.presigned,
			"The request path is not a consistent encoding of the path it names.")
	}
	if !hmac.Equal([]byte(signature(r, s, uri)), []byte(s.signature)) {
		return nil, newError(KindSignatureMismatch, s.presigned, "The request signature we "+
			"calculated does not match the signature you provided. Check your AWS Secret "+
			"Access Key and signing method.")
	}

	v.replaceBody(r, s, body)
	return s, nil
}

// mapError passes e through the WithErrorMap function. A failure must never
// read as success, so a map that returns nil gets e back.
func (v *Verifier) mapError(e *Error) error {
	if v.mapErr == nil {
		return e
	}
	if err := v.mapErr(e); err != nil {
		return err
	}
	return e
}

// parse reads what r claims about its signature, from a presigned URL when
// r carries one and they are accepted, and from its Authorization header
// otherwise.
func (v *Verifier) parse(r *http.Request) (*signed, *Error) {
	switch {
	case v.presign && r.URL.Query().Get("X-Amz-Algorithm") != "":
		return v.parsePresigned(r)
	case r.Header.Get("Authorization") != "":
		return v.parseHeader(r)
	default:
		return nil, newError(KindMissingAuth, false, "Missing Authentication Token")
	}
}

func (v *Verifier) parseHeader(r *http.Request) (*signed, *Error) {
	auth, err := parseAuthorization(r.Header.Get("Authorization"))
	if err != nil {
		return nil, err
	}
	signedHeaders, ok := parseSignedHeaders(auth.signedHeaders)
	if !ok {
		return nil, malformedSignedHeaders(false)
	}

	date, perr := time.Parse(amzDateFmt, r.Header.Get("X-Amz-Date"))
	if perr != nil {
		return nil, newError(KindInvalidDate, false,
			"AWS authentication requires a valid X-Amz-Date header")
	}
	if skew := v.now().Sub(date); skew > v.maxSkew || skew < -v.maxSkew {
		return nil, newError(KindRequestTimeTooSkewed, false, "Signature expired: the "+
			"difference between the request time and the current time is too large.")
	}

	s := &signed{
		date:          date,
		signature:     auth.signature,
		payloadHash:   r.Header.Get("X-Amz-Content-Sha256"),
		signedHeaders: signedHeaders,
	}
	if v.streamed && s.payloadHash == "" {
		return nil, newError(KindMissingPayloadHash, false,
			"Missing required header for this request: x-amz-content-sha256")
	}
	return v.finishParse(r, s, auth.credential)
}

func (v *Verifier) parsePresigned(r *http.Request) (*signed, *Error) {
	q := r.URL.Query()
	if err := checkPresignParams(q); err != nil {
		return nil, err
	}
	signedHeaders, ok := parseSignedHeaders(q.Get("X-Amz-SignedHeaders"))
	if !ok {
		return nil, malformedSignedHeaders(true)
	}

	date, err := time.Parse(amzDateFmt, q.Get("X-Amz-Date"))
	if err != nil {
		return nil, newError(KindInvalidDate, true,
			"X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"")
	}
	maxExpires := int(v.maxExpiry / time.Second)
	expires, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	// AWS takes 1 to 604800 seconds; a URL valid for none is no URL.
	if err != nil || expires < 1 || expires > maxExpires {
		return nil, newError(KindInvalidExpires, true, "X-Amz-Expires must be a number of "+
			"seconds between 1 and "+strconv.Itoa(maxExpires))
	}
	if e := v.checkPresignWindow(date, time.Duration(expires)*time.Second); e != nil {
		return nil, e
	}

	s := &signed{
		date:          date,
		signature:     q.Get("X-Amz-Signature"),
		payloadHash:   r.Header.Get("X-Amz-Content-Sha256"),
		signedHeaders: signedHeaders,
		presigned:     true,
	}
	if v.streamed && s.payloadHash == "" {
		s.payloadHash = unsignedPayload
	}
	return v.finishParse(r, s, q.Get("X-Amz-Credential"))
}

// checkPresignWindow refuses a presigned URL that is not valid now. Its
// window opens at X-Amz-Date, which may be ahead of the server's clock by no
// more than the allowed skew, as S3 allows, and lasts X-Amz-Expires, which
// is at most the maximum expiry. A URL is so valid for no longer than the
// skew plus the maximum expiry from now, however it is dated.
func (v *Verifier) checkPresignWindow(date time.Time, expires time.Duration) *Error {
	now := v.now()
	if date.After(now.Add(v.maxSkew)) {
		return newError(KindRequestNotYetValid, true, "Request is not yet valid")
	}
	if now.After(date.Add(expires)) {
		return newError(KindExpired, true, "Request has expired")
	}
	return nil
}

// finishParse checks the signed headers, the session token and the
// credential, and looks up the signing key the credential names.
func (v *Verifier) finishParse(r *http.Request, s *signed, cred string) (*signed, *Error) {
	if err := v.requireSignedHeaders(s); err != nil {
		return nil, err
	}
	if err := requireAmzHeadersSigned(r, s); err != nil {
		return nil, err
	}
	if err := readSessionToken(r, s); err != nil {
		return nil, err
	}

	c, ok := parseCredential(cred)
	if !ok {
		return nil, newError(KindMalformedCredential, s.presigned, "The credential is "+
			"malformed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\".")
	}
	s.cred = c

	key, err := v.signingKey(r, s)
	if err != nil {
		return nil, err
	}
	s.key = key

	if c.date != s.date.Format(dateFmt) {
		return nil, newError(KindCredentialDateMismatch, s.presigned,
			"The credential date does not match the request date.")
	}
	if v.service != "" && c.service != v.service {
		return nil, newError(KindWrongService, s.presigned,
			"Credential should be scoped to correct service: '"+v.service+"'.")
	}
	return s, nil
}

// requireSignedHeaders rejects a signature that leaves out a required
// header. X-Amz-Target, for one, names the operation of an AWS JSON call:
// left unsigned, it would let whoever relays a signed read turn it into a
// delete, since the two carry the same body.
func (v *Verifier) requireSignedHeaders(s *signed) *Error {
	for _, want := range v.required {
		if s.presigned && want == "x-amz-date" {
			// A presigned URL signs X-Amz-Date in its query.
			continue
		}
		if !signsHeader(s, want) {
			return unsignedHeader(s, want)
		}
	}
	return nil
}

// requireAmzHeadersSigned rejects a request that carries an x-amz-* header
// the signature does not cover, naming the first in sorted order. AWS
// requires every x-amz-* header sent to be signed: left unsigned, one such
// as X-Amz-Copy-Source would let whoever relays a signed upload turn it into
// a copy of another object. The SDK signer signs every one it sends; on a
// presigned URL it hoists those it does not keep as headers into the query,
// where the canonical query covers them.
func requireAmzHeadersSigned(r *http.Request, s *signed) *Error {
	var unsigned []string
	for name := range r.Header {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-amz-") && !signsHeader(s, lower) {
			unsigned = append(unsigned, lower)
		}
	}
	if len(unsigned) == 0 {
		return nil
	}
	slices.Sort(unsigned)
	return unsignedHeader(s, unsigned[0])
}

// signsHeader reports whether s signs name, a lowercase header name. The
// list is sorted and its names exact, as parseSignedHeaders checked.
func signsHeader(s *signed, name string) bool {
	_, found := slices.BinarySearch(s.signedHeaders, name)
	return found
}

func unsignedHeader(s *signed, name string) *Error {
	e := newError(KindUnsignedHeader, s.presigned,
		"The request signature must cover the "+name+" header.")
	e.Header = name
	return e
}

// readSessionToken takes the session token from the X-Amz-Security-Token
// header or query parameter, as the SDK signer sends it: a header on a
// signed request, a parameter of a presigned URL. A parameter is part of the
// canonical query, so always signed; a header, like every x-amz-* header,
// has been checked to be among the signed headers.
func readSessionToken(r *http.Request, s *signed) *Error {
	header := r.Header.Get(tokenHeader)
	param := r.URL.Query().Get(tokenHeader)
	if header != "" && param != "" && header != param {
		return newError(KindInvalidSessionToken, s.presigned,
			"The security token included in the request is invalid.")
	}
	s.sessionToken = header
	if s.sessionToken == "" {
		s.sessionToken = param
	}
	return nil
}

// signingKey asks the KeySource for the key s's credential signs with. It is
// looked up before the credential's date is checked, so an unknown access
// key is reported as such whatever else is wrong with the credential.
func (v *Verifier) signingKey(r *http.Request, s *signed) (Key, *Error) {
	key, err := v.keys.SigningKey(r.Context(), s.scope())
	if err != nil {
		e := keyError(err, s.presigned)
		e.Err = err
		return Key{}, e
	}
	if len(key.Signing) == 0 || key.Principal.AccountID == "" {
		// A key with no principal account would verify a request as no one.
		return Key{}, newError(KindKeyLookupFailed, s.presigned,
			"The signing key could not be found.")
	}
	return key, nil
}

// keyError is the verification failure a KeySource error stands for.
func keyError(err error, presigned bool) *Error {
	switch {
	case errors.Is(err, ErrUnknownAccessKey):
		return newError(KindUnknownAccessKey, presigned,
			"The security token included in the request is invalid.")
	case errors.Is(err, ErrInvalidSessionToken):
		return newError(KindInvalidSessionToken, presigned,
			"The security token included in the request is invalid.")
	case errors.Is(err, ErrExpiredSessionToken):
		return newError(KindExpiredSessionToken, presigned,
			"The security token included in the request is expired")
	default:
		return newError(KindKeyLookupFailed, presigned, "The signing key could not be found.")
	}
}
