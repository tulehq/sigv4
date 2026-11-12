package sigv4

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// The JSON services' fixtures: the AWS documentation's example key.
const (
	testAccessKey = "AKIDEXAMPLE"
	testSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	jsonType      = "application/x-amz-json-1.1"
	targetHeader  = "X-Amz-Target"
)

// signedAt is when the JSON fixtures are signed, and the clock they are
// verified at.
var signedAt = time.Date(2026, time.March, 4, 5, 6, 7, 0, time.UTC)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func fixedClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// mustStatic returns NewStaticKey(cfg), failing t on an error.
func mustStatic(t testing.TB, cfg StaticKeyConfig) *StaticKey {
	t.Helper()
	k, err := NewStaticKey(cfg)
	if err != nil {
		t.Fatalf("NewStaticKey: %v", err)
	}
	return k
}

// check verifies r, keeping only the error, for the tests that need no more.
func (v *Verifier) check(r *http.Request) error {
	_, err := v.Verify(r)
	return err
}

func mustNew(t *testing.T, keys KeySource, opts ...Option) *Verifier {
	t.Helper()
	v, err := New(keys, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return v
}

// s3Options configure a verifier the way object-store verifies today.
func s3Options() []Option {
	return []Option{
		WithPresignedURLs(true),
		WithStreamedPayload(),
		WithAnyPayloadHash(true),
		WithRequiredSignedHeaders(),
	}
}

// jsonOptions configure a verifier the way secret-store and accounts verify
// today: the defaults, plus x-amz-target among the signed headers.
func jsonOptions() []Option {
	return []Option{WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target")}
}

// jsonService is one of the AWS JSON services the verifier stands behind.
type jsonService struct {
	name         string // the signing name
	host         string
	readTarget   string // a read the tests sign
	removeTarget string // the destructive call a relay would rather it were
	body         string
	otherBody    string
	invalidInput string // the error type the service answers bad input with
}

var jsonServices = []jsonService{
	{
		name:         "secretsmanager",
		host:         "secretsmanager.localhost",
		readTarget:   "secretsmanager.GetSecretValue",
		removeTarget: "secretsmanager.DeleteSecret",
		body:         `{"SecretId":"example/app"}`,
		otherBody:    `{"SecretId":"example/app","ForceDeleteWithoutRecovery":true}`,
		invalidInput: "InvalidParameterException",
	},
	{
		name:         "organizations",
		host:         "organizations.localhost",
		readTarget:   "AWSOrganizationsV20161128.DescribeAccount",
		removeTarget: "AWSOrganizationsV20161128.RemoveAccountFromOrganization",
		body:         `{"AccountId":"111111111111"}`,
		otherBody:    `{"AccountId":"222222222222"}`,
		invalidInput: "InvalidInputException",
	},
}

func jsonVerifier(t *testing.T, opts ...Option) *Verifier {
	t.Helper()
	all := append(jsonOptions(), WithClock(fixedClock(signedAt)))
	return mustNew(
		t,
		mustStatic(t, StaticKeyConfig{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}),
		append(all, opts...)...)
}

// signJSON builds a request signed the way the AWS SDK signs an AWS JSON
// call: the payload hash is signed but not sent.
func (svc jsonService) signJSON(t *testing.T, body string) *http.Request {
	t.Helper()
	return svc.signWith(t, body, sha256Hex(body), map[string]string{
		"Content-Type": jsonType,
		targetHeader:   svc.readTarget,
	})
}

// signWith signs a request the way a hand-rolled client could, with the
// payload hash and the header set the caller chooses, so a test can produce
// the requests the AWS SDK never would.
func (svc jsonService) signWith(
	t *testing.T, body, payloadHash string, headers map[string]string,
) *http.Request {
	t.Helper()

	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "/", strings.NewReader(body),
	)
	req.Host = svc.host
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	creds := aws.Credentials{AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey}
	if err := v4.NewSigner().SignHTTP(
		context.Background(), creds, req, payloadHash, svc.name, "us-east-1", signedAt,
	); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	return req
}

// wire is a service's error response, as a client sees it.
type wire struct {
	code    string
	message string
	status  int
}

// wireError is what the test error maps turn an *Error into, standing in for
// a service's own error type.
type wireError struct {
	wire
}

func (e *wireError) Error() string { return e.code + ": " + e.message }

func s3Map(e *Error) error   { return &wireError{s3Wire(e)} }
func jsonMap(e *Error) error { return &wireError{jsonWire(e, "<invalid>")} }
func wantWire(t *testing.T, err error, want wire) {
	t.Helper()
	var we *wireError
	if !errors.As(err, &we) {
		t.Fatalf("error = %v, want a wire error", err)
	}
	if we.wire != want {
		t.Fatalf("wire error =\n  %d %s %q\nwant\n  %d %s %q",
			we.status, we.code, we.message, want.status, want.code, want.message)
	}
}

// s3Code is the S3 error object-store answers a Kind with: header for an
// Authorization header request, query for a presigned URL when it differs.
// An empty message stands for the Error's own.
type s3Code struct {
	header wire
	query  wire
}

func s3Bad(code string) wire       { return wire{status: http.StatusBadRequest, code: code} }
func s3Forbidden(code string) wire { return wire{status: http.StatusForbidden, code: code} }

var (
	headerMalformed = s3Bad("AuthorizationHeaderMalformed")
	queryMalformed  = s3Bad("AuthorizationQueryParametersError")
)

var s3Codes = map[Kind]s3Code{
	KindMissingAuth: {header: wire{
		status: http.StatusForbidden, code: "AccessDenied", message: "Access Denied",
	}},
	KindUnsupportedAlgorithm:   {header: s3Bad("InvalidRequest"), query: queryMalformed},
	KindIncompleteAuth:         {header: headerMalformed, query: queryMalformed},
	KindMalformedCredential:    {header: headerMalformed, query: queryMalformed},
	KindCredentialDateMismatch: {header: headerMalformed, query: queryMalformed},
	KindInvalidDate:            {header: s3Forbidden("AccessDenied"), query: queryMalformed},
	KindInvalidExpires:         {header: queryMalformed},
	KindExpired:                {header: s3Forbidden("AccessDenied")},
	KindRequestNotYetValid:     {header: s3Forbidden("AccessDenied")},
	KindUnsignedHeader: {header: wire{
		status: http.StatusForbidden, code: "AccessDenied",
		message: "There were headers present in the request which were not signed",
	}},
	KindInvalidSessionToken: {header: wire{
		status: http.StatusBadRequest, code: "InvalidToken",
		message: "The provided token is malformed or otherwise invalid.",
	}},
	KindExpiredSessionToken: {header: wire{
		status: http.StatusBadRequest, code: "ExpiredToken",
		message: "The provided token has expired.",
	}},
	KindMissingPayloadHash:  {header: s3Bad("InvalidRequest")},
	KindPayloadHashMismatch: {header: s3Bad("XAmzContentSHA256Mismatch")},
	// S3 has no error for a body it cannot verify, since it accepts unsigned
	// payloads; InvalidRequest is object-store's choice.
	KindUnverifiedPayload: {header: s3Bad("InvalidRequest")},
	// ReadBody reads small control documents, which S3 bounds with
	// MaxMessageLengthExceeded.
	KindBodyTooLarge: {header: wire{
		status: http.StatusBadRequest, code: "MaxMessageLengthExceeded",
		message: "Your request was too big.",
	}},
	KindRequestTimeTooSkewed: {header: wire{
		status: http.StatusForbidden, code: "RequestTimeTooSkewed",
		message: "The difference between the request time and the current time is too large.",
	}},
	KindUnknownAccessKey: {header: wire{
		status: http.StatusForbidden, code: "InvalidAccessKeyId",
		message: "The AWS Access Key Id you provided does not exist in our records.",
	}},
	KindSignatureMismatch: {header: wire{
		status: http.StatusForbidden, code: "SignatureDoesNotMatch",
		message: "The request signature we calculated does not match the signature you " +
			"provided. Check your key and signing method.",
	}},
}

// s3Wire maps an *Error to the S3 error object-store answers with today. It
// is the map object-store is to adopt, kept here as the executable record of
// what preserving its behavior means.
func s3Wire(e *Error) wire {
	c, ok := s3Codes[e.Kind]
	if !ok {
		return wire{
			status: http.StatusInternalServerError, code: "InternalError",
			message: "We encountered an internal error. Please try again.",
		}
	}
	w := c.header
	if e.Presigned && c.query.code != "" {
		w = c.query
	}
	if w.message == "" {
		w.message = e.Message
	}
	return w
}

// jsonWire maps an *Error to the AWS JSON error secret-store and accounts
// answer with today. invalidInput is the service's bad-input type:
// InvalidParameterException for Secrets Manager, InvalidInputException for
// Organizations.
func jsonWire(e *Error, invalidInput string) wire {
	switch e.Kind {
	case KindMissingAuth:
		return wire{
			status: http.StatusForbidden, code: "MissingAuthenticationTokenException",
			message: e.Message,
		}
	case KindUnsupportedAlgorithm, KindIncompleteAuth, KindInvalidDate, KindUnsignedHeader,
		KindMalformedCredential, KindCredentialDateMismatch, KindPayloadHashNotAccepted:
		return wire{
			status: http.StatusForbidden, code: "IncompleteSignatureException", message: e.Message,
		}
	case KindRequestTimeTooSkewed, KindSignatureMismatch:
		return wire{
			status: http.StatusForbidden, code: "InvalidSignatureException", message: e.Message,
		}
	case KindUnknownAccessKey, KindInvalidSessionToken:
		return wire{
			status: http.StatusForbidden, code: "UnrecognizedClientException", message: e.Message,
		}
	case KindExpiredSessionToken:
		return wire{status: http.StatusForbidden, code: "ExpiredTokenException", message: e.Message}
	case KindPayloadHashMismatch, KindBodyUnreadable:
		return wire{status: http.StatusBadRequest, code: invalidInput, message: e.Message}
	case KindBodyTooLarge:
		return wire{
			status:  http.StatusRequestEntityTooLarge,
			code:    invalidInput,
			message: e.Message,
		}
	default:
		return wire{
			status: http.StatusInternalServerError, code: "InternalFailure",
			message: "An internal error occurred.",
		}
	}
}

// wantKind fails unless err is an *Error of kind.
func wantKind(t *testing.T, err error, kind Kind) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("error = %v, want an *Error of kind %s", err, kind)
	}
	if e.Kind != kind {
		t.Fatalf("kind = %s (%q), want %s", e.Kind, e.Message, kind)
	}
}

// asKind fails unless err is an *Error of kind, and returns it.
func asKind(t *testing.T, err error, kind Kind) *Error {
	t.Helper()
	wantKind(t, err, kind)
	var e *Error
	errors.As(err, &e)
	return e
}
