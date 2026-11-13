package sigv4

// Every error the three services' verifiers return today, by condition, with
// the status, code and message a client sees. Each row goes through Verify
// with the service's options and its error map, so a row passing means the
// service can rebuild that response from the Kind and message.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type tableRow struct {
	request func(t *testing.T) *http.Request
	name    string
	want    wire
	opts    []Option
	// readBody fails the row on the body's read rather than on Verify.
	readBody bool
}

const (
	s3Target       = "http://localhost:9000/bucket/key"
	credMalformed  = "The credential is malformed; expecting \"<YOUR-AKID>/YYYYMMDD/REGION/SERVICE/aws4_request\"."
	credDateText   = "The credential date does not match the request date."
	mechanismText  = "The authorization mechanism you have provided is not supported. Please use AWS4-HMAC-SHA256."
	incompleteText = "The authorization header is malformed; it must contain Credential, SignedHeaders and Signature."
	dateHeaderText = "AWS authentication requires a valid X-Amz-Date header"
)

func s3Header(t *testing.T) *http.Request {
	t.Helper()
	return s3SignedRequest(t, s3Target, s3AccessKey, s3SecretKey)
}

func s3Unauthenticated(t *testing.T) *http.Request {
	t.Helper()
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, s3Target, nil)
}

func s3Presigned(t *testing.T) *http.Request {
	t.Helper()
	return s3PresignedRequest(t, s3Target, time.Hour)
}

// withAuth returns build with its Authorization header rewritten by edit.
func withAuth(
	build func(*testing.T) *http.Request, edit func(string) string,
) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		r := build(t)
		r.Header.Set("Authorization", edit(r.Header.Get("Authorization")))
		return r
	}
}

// withQuery returns build with its query parameter name set to value, or
// removed when value is empty.
func withQuery(
	build func(*testing.T) *http.Request,
	name, value string,
) func(*testing.T) *http.Request {
	return func(t *testing.T) *http.Request {
		t.Helper()
		r := build(t)
		q := r.URL.Query()
		if value == "" {
			q.Del(name)
		} else {
			q.Set(name, value)
		}
		r.URL.RawQuery = q.Encode()
		return r
	}
}

func replacer(old, repl string) func(string) string {
	return func(s string) string { return strings.Replace(s, old, repl, 1) }
}

func s3HeaderRows() []tableRow {
	forbidden, bad := http.StatusForbidden, http.StatusBadRequest
	return []tableRow{
		{
			name:    "no authentication",
			request: s3Unauthenticated,
			want:    wire{status: forbidden, code: "AccessDenied", message: "Access Denied"},
		},
		{
			name:    "unsupported mechanism",
			request: withAuth(s3Header, func(string) string { return "AWS AKID:abc" }),
			want:    wire{status: bad, code: "InvalidRequest", message: mechanismText},
		},
		{
			name: "header without Signature",
			request: withAuth(s3Header, func(a string) string {
				before, _, _ := strings.Cut(a, ", Signature=")
				return before
			}),
			want: wire{status: bad, code: "AuthorizationHeaderMalformed", message: incompleteText},
		},
		{
			name: "invalid X-Amz-Date header",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := s3Header(t)
				r.Header.Set("X-Amz-Date", "yesterday")
				return r
			},
			want: wire{status: forbidden, code: "AccessDenied", message: dateHeaderText},
		},
		{
			name:    "request time too skewed",
			request: s3Header,
			opts:    []Option{WithClock(fixedClock(s3SignTime.Add(-time.Hour)))},
			want: wire{status: forbidden, code: "RequestTimeTooSkewed", message: "The difference " +
				"between the request time and the current time is too large."},
		},
		{
			name: "missing x-amz-content-sha256",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := s3Header(t)
				r.Header.Del("X-Amz-Content-Sha256")
				return r
			},
			want: wire{
				status: bad,
				code:   "InvalidRequest",
				message: "Missing required header for " +
					"this request: x-amz-content-sha256",
			},
		},
	}
}

func s3SignatureRows() []tableRow {
	forbidden, bad := http.StatusForbidden, http.StatusBadRequest
	return []tableRow{
		{
			name:    "malformed credential",
			request: withAuth(s3Header, replacer("/aws4_request", "/aws5_request")),
			want: wire{
				status:  bad,
				code:    "AuthorizationHeaderMalformed",
				message: credMalformed,
			},
		},
		{
			name:    "unknown access key",
			request: withAuth(s3Header, replacer("Credential=AKID/", "Credential=OTHER/")),
			want: wire{
				status: forbidden,
				code:   "InvalidAccessKeyId",
				message: "The AWS Access Key " +
					"Id you provided does not exist in our records.",
			},
		},
		{
			name:    "credential date mismatch",
			request: withAuth(s3Header, replacer("/20261015/", "/20261014/")),
			want:    wire{status: bad, code: "AuthorizationHeaderMalformed", message: credDateText},
		},
		{
			name:    "signature mismatch",
			request: withAuth(s3Header, replacer("Signature=", "Signature=0")),
			want: wire{
				status: http.StatusForbidden,
				code:   "SignatureDoesNotMatch",
				message: "The " +
					"request signature we calculated does not match the signature you provided. " +
					"Check your key and signing method.",
			},
		},
		{
			name: "body does not match x-amz-content-sha256",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := s3Header(t)
				r.Body = io.NopCloser(strings.NewReader("tampered"))
				return r
			},
			readBody: true,
			want: wire{
				status: http.StatusBadRequest, code: "XAmzContentSHA256Mismatch",
				message: hashMismatchText,
			},
		},
	}
}

func s3PresignRows() []tableRow {
	const aqpe = "AuthorizationQueryParametersError"
	bad := http.StatusBadRequest
	return []tableRow{
		{
			name:    "presign algorithm",
			request: withQuery(s3Presigned, "X-Amz-Algorithm", "AWS4-HMAC-SHA1"),
			want: wire{
				status: bad, code: aqpe,
				message: "X-Amz-Algorithm only supports \"AWS4-HMAC-SHA256\"",
			},
		},
		{
			name:    "presign missing parameter",
			request: withQuery(s3Presigned, "X-Amz-SignedHeaders", ""),
			want: wire{status: bad, code: aqpe, message: "Query-string authentication version 4 " +
				"requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, " +
				"X-Amz-SignedHeaders, and X-Amz-Expires parameters."},
		},
		{
			name:    "presign invalid date",
			request: withQuery(s3Presigned, "X-Amz-Date", "20261015"),
			want: wire{
				status: bad, code: aqpe,
				message: "X-Amz-Date must be in the ISO8601 Long Format \"yyyyMMdd'T'HHmmss'Z'\"",
			},
		},
		{
			name:    "presign expiry over seven days",
			request: withQuery(s3Presigned, "X-Amz-Expires", "604801"),
			want: wire{
				status: bad, code: aqpe,
				message: "X-Amz-Expires must be a number of seconds between 1 and 604800",
			},
		},
		{
			name:    "presign expiry not a number",
			request: withQuery(s3Presigned, "X-Amz-Expires", "-1"),
			want: wire{
				status: bad, code: aqpe,
				message: "X-Amz-Expires must be a number of seconds between 1 and 604800",
			},
		},
		{
			name:    "presign expired",
			request: s3Presigned,
			opts:    []Option{WithClock(fixedClock(s3SignTime.Add(2 * time.Hour)))},
			want: wire{
				status: http.StatusForbidden, code: "AccessDenied",
				message: "Request has expired",
			},
		},
	}
}

func s3PresignCredentialRows() []tableRow {
	const aqpe = "AuthorizationQueryParametersError"
	return []tableRow{
		{
			name:    "presign dated ahead of the clock",
			request: s3Presigned,
			opts:    []Option{WithClock(fixedClock(s3SignTime.Add(-time.Hour)))},
			want: wire{
				status: http.StatusForbidden, code: "AccessDenied",
				message: "Request is not yet valid",
			},
		},
		{
			name: "presign malformed credential",
			request: withQuery(s3Presigned, "X-Amz-Credential",
				"AKID/20261015/us-east-1/s3"),
			want: wire{status: http.StatusBadRequest, code: aqpe, message: credMalformed},
		},
		{
			name: "presign unknown access key",
			request: withQuery(s3Presigned, "X-Amz-Credential",
				"OTHER/20261015/us-east-1/s3/aws4_request"),
			want: wire{
				status: http.StatusForbidden, code: "InvalidAccessKeyId",
				message: "The AWS Access Key Id you provided does not exist in our records.",
			},
		},
		{
			name: "presign credential date mismatch",
			request: withQuery(s3Presigned, "X-Amz-Credential",
				"AKID/20261014/us-east-1/s3/aws4_request"),
			want: wire{status: http.StatusBadRequest, code: aqpe, message: credDateText},
		},
		{
			name:    "presign signature mismatch",
			request: withQuery(s3Presigned, "X-Amz-Signature", strings.Repeat("0", 64)),
			want: wire{
				status: http.StatusForbidden,
				code:   "SignatureDoesNotMatch",
				message: "The " +
					"request signature we calculated does not match the signature you provided. " +
					"Check your key and signing method.",
			},
		},
	}
}

func TestS3ErrorTable(t *testing.T) {
	rows := append(s3HeaderRows(), s3SignatureRows()...)
	rows = append(rows, s3PresignRows()...)
	rows = append(rows, s3PresignCredentialRows()...)
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			v := s3Verifier(t, append([]Option{WithErrorMap(s3Map)}, row.opts...)...)
			runRow(t, v, row)
		})
	}
}

func runRow(t *testing.T, v *Verifier, row tableRow) {
	t.Helper()
	r := row.request(t)
	err := v.check(r)
	if row.readBody {
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		_, err = io.ReadAll(r.Body)
	}
	wantWire(t, err, row.want)
}

// The JSON rows are shared by secret-store and accounts, each row answered
// with the service's own status and bad-input type.

func jsonHeaderRows(svc jsonService) []tableRow {
	forbidden := http.StatusForbidden
	signed := func(t *testing.T) *http.Request {
		t.Helper()
		return svc.signJSON(t, svc.body)
	}
	return []tableRow{
		{
			name: "no authentication",
			// X-Amz-* query parameters are not a presigned URL here.
			request: withQuery(func(t *testing.T) *http.Request {
				t.Helper()
				r := signed(t)
				r.Header.Del("Authorization")
				return r
			}, "X-Amz-Algorithm", algorithm),
			want: wire{
				status: forbidden, code: typeMissingAuthToken,
				message: "Missing Authentication Token",
			},
		},
		{
			name:    "unsupported algorithm",
			request: withAuth(signed, replacer(algorithm, "AWS4-HMAC-SHA512")),
			want:    svc.incomplete(mechanismText),
		},
		{
			name: "header without SignedHeaders",
			request: withAuth(signed, func(a string) string {
				return strings.Replace(a, "SignedHeaders=", "Signed=", 1)
			}),
			want: svc.incomplete(incompleteText),
		},
		{
			name: "missing X-Amz-Date",
			request: func(t *testing.T) *http.Request {
				t.Helper()
				r := signed(t)
				r.Header.Del("X-Amz-Date")
				return r
			},
			want: svc.incomplete(dateHeaderText),
		},
		{
			name:    "request time too skewed",
			request: signed,
			opts:    []Option{WithClock(fixedClock(signedAt.Add(16 * time.Minute)))},
			want: wire{
				status: forbidden,
				code:   typeInvalidSignature,
				message: "Signature expired: " +
					"the difference between the request time and the current time is too large.",
			},
		},
	}
}

func jsonSignedHeaderRows(svc jsonService) []tableRow {
	forbidden := http.StatusForbidden
	signed := func(t *testing.T) *http.Request {
		t.Helper()
		return svc.signJSON(t, svc.body)
	}
	drop := func(name string) func(*testing.T) *http.Request {
		return withAuth(signed, func(a string) string {
			a = strings.Replace(a, name+";", "", 1)
			return strings.Replace(a, ";"+name, "", 1)
		})
	}
	return []tableRow{
		{
			name:    "host not signed",
			request: drop("host"),
			want:    svc.incomplete("The request signature must cover the host header."),
		},
		{
			name:    "x-amz-date not signed",
			request: drop("x-amz-date"),
			want:    svc.incomplete("The request signature must cover the x-amz-date header."),
		},
		{
			name:    "x-amz-target not signed",
			request: drop("x-amz-target"),
			want:    svc.incomplete("The request signature must cover the x-amz-target header."),
		},
		{
			name:    "malformed credential",
			request: withAuth(signed, replacer("/aws4_request", "")),
			want:    svc.incomplete(credMalformed),
		},
		{
			name:    "unknown access key",
			request: withAuth(signed, replacer("Credential="+testAccessKey, "Credential=OTHER")),
			want: wire{
				status: forbidden, code: typeUnrecognizedClient,
				message: "The security token included in the request is invalid.",
			},
		},
		{
			name:    "credential date mismatch",
			request: withAuth(signed, replacer("/20260304/", "/20260303/")),
			want:    svc.incomplete(credDateText),
		},
	}
}

// errConnReset is what failingReader fails with.
var errConnReset = errors.New("connection reset")

// failingReader fails every read, as a client that drops mid-body does.
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errConnReset }

func jsonBodyRows(svc jsonService) []tableRow {
	withBody := func(body io.Reader) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			t.Helper()
			r := svc.signJSON(t, svc.body)
			r.Body = io.NopCloser(body)
			return r
		}
	}
	return []tableRow{
		{
			name:    "body unreadable",
			request: withBody(failingReader{}),
			want: wire{
				status: http.StatusBadRequest, code: svc.invalidInput,
				message: "The request body could not be read.",
			},
		},
		{
			name:    "body too large",
			request: withBody(strings.NewReader(strings.Repeat("a", DefaultMaxBodySize+1))),
			want: wire{
				status: http.StatusRequestEntityTooLarge, code: svc.invalidInput,
				message: "The request body is larger than this service accepts.",
			},
		},
	}
}

func jsonPayloadRows(svc jsonService) []tableRow {
	declared := func(hash string) func(*testing.T) *http.Request {
		return func(t *testing.T) *http.Request {
			t.Helper()
			return svc.signWith(t, svc.body, hash, map[string]string{
				"Content-Type":         jsonType,
				targetHeader:           svc.readTarget,
				"X-Amz-Content-Sha256": hash,
			})
		}
	}
	notAccepted := svc.incomplete("x-amz-" +
		"content-sha256 must be the hex SHA-256 of the request body; UNSIGNED-PAYLOAD is not " +
		"accepted.")
	return []tableRow{
		{name: "UNSIGNED-PAYLOAD", request: declared(unsignedPayload), want: notAccepted},
		{
			name:    "STREAMING payload",
			request: declared("STREAMING-AWS4-HMAC-SHA256-PAYLOAD"),
			want:    notAccepted,
		},
		{name: "non-hex payload hash", request: declared("not-a-hash"), want: notAccepted},
		{
			name:    "declared hash does not match the body",
			request: declared(strings.Repeat("a", 64)),
			want: wire{
				status: http.StatusBadRequest, code: svc.invalidInput,
				message: hashMismatchText,
			},
		},
		{
			name: "signature mismatch",
			request: withAuth(func(t *testing.T) *http.Request {
				t.Helper()
				return svc.signJSON(t, svc.body)
			}, replacer("Signature=", "Signature=0")),
			want: wire{status: http.StatusForbidden, code: typeInvalidSignature, message: "The " +
				"request signature we calculated does not match the signature you provided. " +
				"Check your AWS Secret Access Key and signing method."},
		},
	}
}

func TestJSONErrorTable(t *testing.T) {
	for _, svc := range jsonServices {
		rows := append(jsonHeaderRows(svc), jsonSignedHeaderRows(svc)...)
		rows = append(rows, jsonBodyRows(svc)...)
		rows = append(rows, jsonPayloadRows(svc)...)
		for _, row := range rows {
			t.Run(svc.name+"/"+row.name, func(t *testing.T) {
				v := jsonVerifier(t, append([]Option{WithErrorMap(svc.wireMap)}, row.opts...)...)
				runRow(t, v, row)
			})
		}
	}
}
