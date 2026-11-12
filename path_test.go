package sigv4

// The canonical URI is encoded twice for every service but S3, as the SDK
// signs it unless DisableURIPathEscaping is set, which only S3 sets.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// restPaths are the paths the path tests sign, as the client escapes them.
var restPaths = []string{"/a%20b", "/a%2Fb", "/a/b%20c/~d+e"}

// signREST signs a GET of path for service the way the SDK signs a non-S3
// call, and returns it as the server parses it.
func signREST(t *testing.T, service, path string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://"+service+".localhost:9000"+path, nil)
	r.Header.Set(targetHeader, service+".Invoke")
	err := v4.NewSigner().SignHTTP(context.Background(), aws.Credentials{
		AccessKeyID: testAccessKey, SecretAccessKey: testSecretKey,
	}, r, sha256Hex(""), service, "us-east-1", signedAt)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return serverRequest(t, r.URL.EscapedPath(), r)
}

func TestNonS3PathsAreEncodedTwice(t *testing.T) {
	for _, service := range []string{"lambda", "secretsmanager"} {
		for _, path := range restPaths {
			t.Run(service+path, func(t *testing.T) {
				if err := jsonVerifier(t).check(signREST(t, service, path)); err != nil {
					t.Fatalf("Verify: %v", err)
				}
				// Encoded once, as S3 is, the same signature does not match.
				wantKind(t, jsonVerifier(t, WithS3PathEncoding()).check(signREST(t, service, path)),
					KindSignatureMismatch)
			})
		}
	}
}

func TestTamperedPathFailsInBothModes(t *testing.T) {
	// Non-S3, encoded twice.
	signed := signREST(t, "lambda", "/a/b")
	for _, target := range []string{"/a/c", "/a%2Fb", "/a/b%20"} {
		wantKind(t, jsonVerifier(t).check(serverRequest(t, target, signed)), KindSignatureMismatch)
	}

	// S3, encoded once.
	s3 := s3Put(t, "http://localhost:9000/bucket/a/b", s3Body, nil)
	for _, target := range []string{"/bucket/a/c", "/bucket/a%2Fb"} {
		r := serverRequest(t, target, s3)
		r.Method = http.MethodPut
		wantKind(t, s3Verifier(t).check(r), KindSignatureMismatch)
	}
}

func TestNonS3RawPathProtections(t *testing.T) {
	// The encoded-slash and RawPath protections hold when the path is
	// encoded twice too.
	signed := signREST(t, "lambda", "/b/a/b%7B")
	if err := jsonVerifier(t).check(serverRequest(t, "/b/a/b%7B", signed)); err != nil {
		t.Fatalf("the signed path: %v", err)
	}
	for _, target := range []string{"/b/a%2Fb%7B", "/b/a%2Fb{"} {
		wantKind(t, jsonVerifier(t).check(serverRequest(t, target, signed)), KindSignatureMismatch)
	}
	r := serverRequest(t, "/b/a%2Fb{", signed)
	r.URL.Path = "/b/other"
	wantKind(t, jsonVerifier(t).check(r), KindIncompleteAuth)
}
