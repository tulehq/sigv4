package sigv4

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// headerBytes is the size of r's headers as sent: names and values.
func headerBytes(r *http.Request) int {
	n := len(r.Host)
	for k, vals := range r.Header {
		for _, v := range vals {
			n += len(k) + len(v)
		}
	}
	return n
}

func FuzzCanonicalHeaders(f *testing.F) {
	f.Add("host;x-amz-date", "X-Amz-Date", "20260304T050607Z", "example.com")
	f.Add("a;host", "A", strings.Repeat("x", 64), "h")
	f.Add(strings.Repeat("a;", 50)+"a", "A", "value", "h")
	f.Add("content-length;host", "X-Amz-Meta-A", "a  \t b ", "h")
	f.Fuzz(func(t *testing.T, list, name, value, host string) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		r.Host = host
		r.Header[http.CanonicalHeaderKey(name)] = []string{value, value}

		names, ok := parseSignedHeaders(list)
		if !ok {
			return
		}
		if !slices.IsSorted(names) || len(slices.Compact(slices.Clone(names))) != len(names) {
			t.Fatalf("names %q are not sorted and unique", names)
		}
		// Each name is canonicalized once, so the canonical headers are no
		// larger than the list, the headers sent and a Content-Length.
		bound := len(list) + 2*len(names) + headerBytes(r) + 20
		if got := len(canonicalHeaders(r, names)); got > bound {
			t.Fatalf("canonical headers %d bytes, bound %d", got, bound)
		}
	})
}

func FuzzVerify(f *testing.F) {
	f.Add(algorithm+" Credential=AKIDEXAMPLE/20260304/us-east-1/s3/aws4_request, "+
		"SignedHeaders=host;x-amz-date, Signature=00", "20260304T050607Z", "a=1", "X-Amz-Meta-A", "b",
		"body", false)
	f.Add("", "", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID/20261015/us-east-1/s3/"+
		"aws4_request&X-Amz-Date=20261015T120000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host&"+
		"X-Amz-Signature=00", "", "", "", true)
	f.Fuzz(func(t *testing.T, auth, date, query, name, value, body string, streamed bool) {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, "/b/k",
			strings.NewReader(body))
		r.URL.RawQuery = query
		r.Header.Set("Authorization", auth)
		r.Header.Set("X-Amz-Date", date)
		r.Header.Set("X-Amz-Content-Sha256", sha256Hex(body))
		if name != "" {
			r.Header[http.CanonicalHeaderKey(name)] = []string{value}
		}

		v := jsonVerifier(t)
		if streamed {
			v = s3Verifier(t)
		}
		got, err := v.Verify(r)
		if (got == nil) == (err == nil) {
			t.Fatalf("Verify = %v, %v: want a request or an error", got, err)
		}
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || e.Kind.String() == "" ||
				strings.HasPrefix(e.Kind.String(), "Kind(") {
				t.Fatalf("error %v is not a known Kind", err)
			}
			return
		}
		if _, err = io.ReadAll(got.Body); err != nil {
			var e *Error
			if !errors.As(err, &e) {
				t.Fatalf("body read: %v", err)
			}
		}
	})
}
