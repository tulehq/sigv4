// Package sigv4 verifies AWS Signature Version 4 on incoming requests, for
// the Tule services that stand in for AWS ones.
//
// Verification is request-level: the signature over the method, path, query,
// signed headers and payload hash is checked, in the Authorization header
// and, when enabled, in presigned URLs. Signing keys come from a KeySource,
// which hands out derived keys rather than secrets; NewStaticKey covers the
// one access key a service accepts today.
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
// body's read fails with it too.
package sigv4

import (
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
	key           []byte
	signedHeaders []string
	presigned     bool
}

// Verify checks r's signature, returning the failure, passed through the
// WithErrorMap function when one is set. On success it replaces r.Body: with
// a buffered payload, by the bytes the signature covered; with a streamed
// one and a hex payload hash, by a reader that fails at EOF if the body does
// not match it.
func (v *Verifier) Verify(r *http.Request) error {
	if e := v.verify(r); e != nil {
		return v.mapError(e)
	}
	return nil
}

func (v *Verifier) verify(r *http.Request) *Error {
	s, err := v.parse(r)
	if err != nil {
		return err
	}

	var body []byte
	if v.streamed {
		if !isHexSHA256(s.payloadHash) {
			if err = v.checkOpaqueHash(s); err != nil {
				return err
			}
		}
	} else if body, err = v.bufferPayload(r, s); err != nil {
		return err
	}

	if !hmac.Equal([]byte(signature(r, s)), []byte(s.signature)) {
		return newError(KindSignatureMismatch, s.presigned, "The request signature we "+
			"calculated does not match the signature you provided. Check your AWS Secret "+
			"Access Key and signing method.")
	}

	v.replaceBody(r, s, body)
	return nil
}

func (v *Verifier) mapError(e *Error) error {
	if v.mapErr == nil {
		return e
	}
	return v.mapErr(e)
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
		signedHeaders: strings.Split(auth.signedHeaders, ";"),
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

	date, err := time.Parse(amzDateFmt, q.Get("X-Amz-Date"))
	if err != nil {
		return nil, newError(KindInvalidDate, true,
			"X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"")
	}
	maxExpires := int(v.maxExpiry / time.Second)
	expires, err := strconv.Atoi(q.Get("X-Amz-Expires"))
	if err != nil || expires < 0 || expires > maxExpires {
		return nil, newError(KindInvalidExpires, true, "X-Amz-Expires must be a number of "+
			"seconds between 0 and "+strconv.Itoa(maxExpires))
	}
	if v.now().After(date.Add(time.Duration(expires) * time.Second)) {
		return nil, newError(KindExpired, true, "Request has expired")
	}

	s := &signed{
		date:          date,
		signature:     q.Get("X-Amz-Signature"),
		payloadHash:   r.Header.Get("X-Amz-Content-Sha256"),
		signedHeaders: strings.Split(q.Get("X-Amz-SignedHeaders"), ";"),
		presigned:     true,
	}
	if v.streamed && s.payloadHash == "" {
		s.payloadHash = unsignedPayload
	}
	return v.finishParse(r, s, q.Get("X-Amz-Credential"))
}

// finishParse checks the signed headers and the credential, and looks up the
// signing key it names.
func (v *Verifier) finishParse(r *http.Request, s *signed, cred string) (*signed, *Error) {
	if err := v.requireSignedHeaders(s); err != nil {
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
		if !slices.ContainsFunc(s.signedHeaders, func(got string) bool {
			return strings.EqualFold(strings.TrimSpace(got), want)
		}) {
			e := newError(KindUnsignedHeader, s.presigned,
				"The request signature must cover the "+want+" header.")
			e.Header = want
			return e
		}
	}
	return nil
}

// signingKey asks the KeySource for the key s's credential signs with. It is
// looked up before the credential's date is checked, so an unknown access
// key is reported as such whatever else is wrong with the credential.
func (v *Verifier) signingKey(r *http.Request, s *signed) ([]byte, *Error) {
	key, err := v.keys.SigningKey(r.Context(), Scope{
		AccessKeyID: s.cred.accessKeyID,
		Date:        s.cred.date,
		Region:      s.cred.region,
		Service:     s.cred.service,
	})
	switch {
	case errors.Is(err, ErrUnknownAccessKey):
		e := newError(KindUnknownAccessKey, s.presigned,
			"The security token included in the request is invalid.")
		e.Err = err
		return nil, e
	case err != nil:
		e := newError(KindKeyLookupFailed, s.presigned, "The signing key could not be found.")
		e.Err = err
		return nil, e
	case len(key) == 0:
		return nil, newError(KindKeyLookupFailed, s.presigned,
			"The signing key could not be found.")
	}
	return key, nil
}
