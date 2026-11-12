package sigv4

// Requests signed by the AWS SDK's own signer, SignHTTP and PresignHTTP, for
// each service the verifier stands behind, verified as signed and then with
// each part of the request tampered with.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const (
	sdkAccessKey = "AKIDEXAMPLE"
	sdkSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
	sdkRegion    = "us-east-1"
)

var sdkTime = time.Date(2026, time.November, 13, 9, 30, 0, 0, time.UTC)

// sdkService is how one service's requests are signed and verified.
type sdkService struct {
	headers map[string]string
	// sign returns the signer for a mode: S3 does not re-escape the path,
	// and a JSON presign keeps X-Amz-Target a signed header.
	signer func(presign bool) *v4.Signer
	name   string
	method string
	target string
	body   string
	opts   []Option
	// sendHash sends the payload hash as X-Amz-Content-Sha256, as the S3
	// client does; the JSON clients sign it without sending it.
	sendHash bool
}

func sdkServices() []sdkService {
	return []sdkService{
		{
			name:   "s3",
			method: http.MethodPut,
			target: "http://localhost:9000/bucket/dir/a%20b.txt?tagging=",
			body:   "object bytes",
			headers: map[string]string{
				"Content-Type": "text/plain",
				"X-Amz-Meta-A": "b",
			},
			sendHash: true,
			signer: func(bool) *v4.Signer {
				return v4.NewSigner(func(o *v4.SignerOptions) { o.DisableURIPathEscaping = true })
			},
			opts: s3Options(),
		},
		sdkJSONService("secretsmanager", "secretsmanager.GetSecretValue",
			`{"SecretId":"example/app"}`),
		sdkJSONService("organizations", "AWSOrganizationsV20161128.DescribeAccount",
			`{"AccountId":"111111111111"}`),
	}
}

func sdkJSONService(name, target, body string) sdkService {
	return sdkService{
		name:   name,
		method: http.MethodPost,
		target: "http://" + name + ".localhost:9010/",
		body:   body,
		headers: map[string]string{
			"Content-Type": jsonType,
			targetHeader:   target,
		},
		signer: func(presign bool) *v4.Signer {
			return v4.NewSigner(func(o *v4.SignerOptions) { o.DisableHeaderHoisting = presign })
		},
		opts: append(jsonOptions(), WithPresignedURLs(true)),
	}
}

func (svc sdkService) verifier(t *testing.T, opts ...Option) *Verifier {
	t.Helper()
	clock := WithClock(fixedClock(sdkTime.Add(time.Minute)))
	all := slices.Concat(svc.opts, []Option{clock}, opts)
	return mustNew(t, NewStaticKey(sdkAccessKey, sdkSecretKey), all...)
}

func (svc sdkService) newRequest(target string) *http.Request {
	r := httptest.NewRequestWithContext(
		context.Background(), svc.method, target, strings.NewReader(svc.body),
	)
	for k, v := range svc.headers {
		r.Header.Set(k, v)
	}
	if svc.sendHash {
		r.Header.Set("X-Amz-Content-Sha256", sha256Hex(svc.body))
	}
	return r
}

// sign returns svc's request signed with the given key, by SignHTTP or by
// PresignHTTP, as the server receives it.
func (svc sdkService) sign(t *testing.T, presign bool, accessKey, secretKey string) *http.Request {
	t.Helper()
	creds := aws.Credentials{AccessKeyID: accessKey, SecretAccessKey: secretKey}
	r := svc.newRequest(svc.target)
	hash := sha256Hex(svc.body)

	if !presign {
		err := svc.signer(false).SignHTTP(
			context.Background(), creds, r, hash, svc.name, sdkRegion, sdkTime,
		)
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		return r
	}

	// PresignHTTP signs the X-Amz-Expires the caller sets.
	q := r.URL.Query()
	q.Set("X-Amz-Expires", "3600")
	r.URL.RawQuery = q.Encode()

	signedURL, headers, err := svc.signer(true).PresignHTTP(
		context.Background(), creds, r, hash, svc.name, sdkRegion, sdkTime,
	)
	if err != nil {
		t.Fatalf("presign: %v", err)
	}
	r = httptest.NewRequestWithContext(
		context.Background(), svc.method, signedURL, strings.NewReader(svc.body),
	)
	for k, vals := range headers {
		if !strings.EqualFold(k, "host") {
			r.Header[k] = vals
		}
	}
	return r
}

// editCredential rewrites the credential, in the Authorization header or the
// X-Amz-Credential parameter.
func editCredential(r *http.Request, old, repl string) {
	if auth := r.Header.Get("Authorization"); auth != "" {
		r.Header.Set("Authorization", strings.Replace(auth, old, repl, 1))
		return
	}
	q := r.URL.Query()
	q.Set("X-Amz-Credential", strings.Replace(q.Get("X-Amz-Credential"), old, repl, 1))
	r.URL.RawQuery = q.Encode()
}

// editDate moves X-Amz-Date, the header or the parameter, a second on.
func editDate(r *http.Request) {
	later := sdkTime.Add(time.Second).Format(amzDateFmt)
	if r.Header.Get("X-Amz-Date") != "" {
		r.Header.Set("X-Amz-Date", later)
		return
	}
	q := r.URL.Query()
	q.Set("X-Amz-Date", later)
	r.URL.RawQuery = q.Encode()
}

type sdkTamper struct {
	apply func(svc sdkService, r *http.Request)
	name  string
}

var sdkTampers = []sdkTamper{
	{name: "method", apply: func(_ sdkService, r *http.Request) { r.Method = http.MethodPatch }},
	{name: "path", apply: func(_ sdkService, r *http.Request) { r.URL.Path += "x" }},
	{name: "query", apply: func(_ sdkService, r *http.Request) {
		q := r.URL.Query()
		q.Add("extra", "1")
		r.URL.RawQuery = q.Encode()
	}},
	{name: "header", apply: func(_ sdkService, r *http.Request) {
		r.Header.Set("Content-Type", "application/octet-stream")
	}},
	{name: "host", apply: func(_ sdkService, r *http.Request) { r.Host = "elsewhere.localhost" }},
	{name: "date", apply: func(_ sdkService, r *http.Request) { editDate(r) }},
	{name: "region", apply: func(_ sdkService, r *http.Request) {
		editCredential(r, "/"+sdkRegion+"/", "/eu-central-1/")
	}},
	{name: "service", apply: func(svc sdkService, r *http.Request) {
		editCredential(r, "/"+svc.name+"/", "/iam/")
	}},
}

func modeName(presign bool) string {
	if presign {
		return "presign"
	}
	return "header"
}

func TestSDKSignedRequestsVerify(t *testing.T) {
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				r := svc.sign(t, presign, sdkAccessKey, sdkSecretKey)
				if err := svc.verifier(t, WithService(svc.name)).Verify(r); err != nil {
					t.Fatalf("Verify: %v", err)
				}
				got, err := io.ReadAll(r.Body)
				if err != nil || string(got) != svc.body {
					t.Fatalf("body = %q, %v; want %q", got, err, svc.body)
				}
			})
		}
	}
}

func TestSDKSignedRequestsTampered(t *testing.T) {
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			for _, tamper := range sdkTampers {
				t.Run(svc.name+"/"+modeName(presign)+"/"+tamper.name, func(t *testing.T) {
					r := svc.sign(t, presign, sdkAccessKey, sdkSecretKey)
					tamper.apply(svc, r)
					wantKind(t, svc.verifier(t).Verify(r), KindSignatureMismatch)
				})
			}
		}
	}
}

func TestSDKSignedRequestsTamperedBody(t *testing.T) {
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				r := svc.sign(t, presign, sdkAccessKey, sdkSecretKey)
				r.Body = io.NopCloser(strings.NewReader(svc.body + " and more"))
				err := svc.verifier(t).Verify(r)

				if !svc.sendHash {
					// The body's own hash is signed, so the signature fails.
					wantKind(t, err, KindSignatureMismatch)
					return
				}
				// The declared hash is signed; the body fails it as it is read.
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				_, err = io.ReadAll(r.Body)
				wantKind(t, err, KindPayloadHashMismatch)
			})
		}
	}
}

func TestSDKSignedRequestsWrongKey(t *testing.T) {
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign)+"/secret", func(t *testing.T) {
				r := svc.sign(t, presign, sdkAccessKey, "not the secret")
				wantKind(t, svc.verifier(t).Verify(r), KindSignatureMismatch)
			})
			t.Run(svc.name+"/"+modeName(presign)+"/access key", func(t *testing.T) {
				r := svc.sign(t, presign, "AKIDOTHER", sdkSecretKey)
				wantKind(t, svc.verifier(t).Verify(r), KindUnknownAccessKey)
			})
		}
	}
}

func TestSDKSignedRequestsWrongService(t *testing.T) {
	// Signed for another service with a valid signature: accepted unless the
	// verifier expects a service.
	for _, svc := range sdkServices() {
		for _, presign := range []bool{false, true} {
			t.Run(svc.name+"/"+modeName(presign), func(t *testing.T) {
				other := svc
				other.name = "iam"
				r := other.sign(t, presign, sdkAccessKey, sdkSecretKey)
				if err := svc.verifier(t).Verify(r); err != nil {
					t.Fatalf("Verify without WithService: %v", err)
				}

				r = other.sign(t, presign, sdkAccessKey, sdkSecretKey)
				e := asKind(t, svc.verifier(t, WithService(svc.name)).Verify(r), KindWrongService)
				if e.Presigned != presign {
					t.Fatalf("Presigned = %v, want %v", e.Presigned, presign)
				}
			})
		}
	}
}

func TestSDKPresignedURLsAreOffByDefault(t *testing.T) {
	// Without WithPresignedURLs, the X-Amz-* parameters are plain query
	// parameters and the request carries no authentication.
	svc := sdkServices()[1]
	svc.opts = jsonOptions()
	r := svc.sign(t, true, sdkAccessKey, sdkSecretKey)
	if _, err := url.ParseQuery(r.URL.RawQuery); err != nil {
		t.Fatalf("query: %v", err)
	}
	wantKind(t, svc.verifier(t).Verify(r), KindMissingAuth)
}
