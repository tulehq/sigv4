package sigv4

import (
	"net/url"
	"strings"
	"testing"
)

type parseAuthCase struct {
	name     string
	auth     string
	want     authHeader
	wantKind Kind
}

func acceptedAuthCases() []parseAuthCase {
	return []parseAuthCase{
		{
			name: "as the SDK writes it",
			auth: "AWS4-HMAC-SHA256 Credential=AKID/20261015/us-east-1/s3/aws4_request, " +
				"SignedHeaders=host;x-amz-date, Signature=abc123",
			want: authHeader{
				credential:    "AKID/20261015/us-east-1/s3/aws4_request",
				signedHeaders: "host;x-amz-date",
				signature:     "abc123",
			},
		},
		{
			name: "no spaces after commas, fields reordered",
			auth: "AWS4-HMAC-SHA256 Signature=s,Credential=c,SignedHeaders=h",
			want: authHeader{credential: "c", signedHeaders: "h", signature: "s"},
		},
		{
			name: "a repeated field keeps its last value",
			auth: "AWS4-HMAC-SHA256 Credential=a, Credential=b, SignedHeaders=h, Signature=s",
			want: authHeader{credential: "b", signedHeaders: "h", signature: "s"},
		},
		{
			name: "unknown fields are ignored",
			auth: "AWS4-HMAC-SHA256 Credential=c, Extra=x, SignedHeaders=h, Signature=s",
			want: authHeader{credential: "c", signedHeaders: "h", signature: "s"},
		},
		{
			name: "a value keeps an equals sign",
			auth: "AWS4-HMAC-SHA256 Credential=c=d, SignedHeaders=h, Signature=s",
			want: authHeader{credential: "c=d", signedHeaders: "h", signature: "s"},
		},
	}
}

func refusedAuthCases() []parseAuthCase {
	return []parseAuthCase{
		{name: "empty", auth: "", wantKind: KindUnsupportedAlgorithm},
		{name: "SigV2", auth: "AWS AKID:abc", wantKind: KindUnsupportedAlgorithm},
		{
			name:     "another algorithm",
			auth:     "AWS4-HMAC-SHA512 Credential=x",
			wantKind: KindUnsupportedAlgorithm,
		},
		{
			name:     "lower-case algorithm",
			auth:     "aws4-hmac-sha256 Credential=c",
			wantKind: KindUnsupportedAlgorithm,
		},
		{
			name:     "no space after the algorithm",
			auth:     "AWS4-HMAC-SHA256",
			wantKind: KindUnsupportedAlgorithm,
		},
		{name: "no fields", auth: "AWS4-HMAC-SHA256 ", wantKind: KindIncompleteAuth},
		{
			name:     "no Signature",
			auth:     "AWS4-HMAC-SHA256 Credential=c, SignedHeaders=h",
			wantKind: KindIncompleteAuth,
		},
		{
			name:     "empty SignedHeaders",
			auth:     "AWS4-HMAC-SHA256 Credential=c, SignedHeaders=, Signature=s",
			wantKind: KindIncompleteAuth,
		},
		{
			name:     "field names are case-sensitive",
			auth:     "AWS4-HMAC-SHA256 credential=c, SignedHeaders=h, Signature=s",
			wantKind: KindIncompleteAuth,
		},
	}
}

func TestParseAuthorization(t *testing.T) {
	for _, tt := range append(acceptedAuthCases(), refusedAuthCases()...) {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuthorization(tt.auth)
			if tt.wantKind != 0 {
				if err == nil || err.Kind != tt.wantKind || err.Presigned {
					t.Fatalf("err = %v, want header %s", err, tt.wantKind)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func FuzzParseAuthorization(f *testing.F) {
	f.Add("AWS4-HMAC-SHA256 Credential=AKID/20261015/us-east-1/s3/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=abc123")
	f.Add("AWS4-HMAC-SHA256 Credential=,SignedHeaders=,Signature=")
	f.Add("AWS AKID:abc")
	f.Add("")
	f.Fuzz(func(t *testing.T, auth string) {
		got, err := parseAuthorization(auth)
		switch {
		case !strings.HasPrefix(auth, algorithm+" "):
			if err == nil || err.Kind != KindUnsupportedAlgorithm {
				t.Fatalf("%q: err = %v, want UnsupportedAlgorithm", auth, err)
			}
		case err != nil:
			if err.Kind != KindIncompleteAuth {
				t.Fatalf("%q: err = %v, want IncompleteAuth", auth, err)
			}
		case got.credential == "" || got.signedHeaders == "" || got.signature == "":
			t.Fatalf("%q: accepted with an empty field: %+v", auth, got)
		}
	})
}

func FuzzParseAuthorizationRoundTrip(f *testing.F) {
	f.Add("AKID/20261015/us-east-1/s3/aws4_request", "host;x-amz-date", "abc123")
	f.Add("c", "h", "s")
	f.Fuzz(func(t *testing.T, cred, headers, sig string) {
		for _, v := range []string{cred, headers, sig} {
			if v == "" || strings.Contains(v, ",") || strings.TrimSpace(v) != v {
				t.Skip("not a value the header format can carry")
			}
		}
		auth := algorithm + " Credential=" + cred + ", SignedHeaders=" + headers +
			", Signature=" + sig
		got, err := parseAuthorization(auth)
		if err != nil {
			t.Fatalf("%q: %v", auth, err)
		}
		want := authHeader{credential: cred, signedHeaders: headers, signature: sig}
		if got != want {
			t.Fatalf("%q: got %+v, want %+v", auth, got, want)
		}
	})
}

func TestParseCredential(t *testing.T) {
	tests := []struct {
		cred   string
		want   credential
		wantOK bool
	}{
		{
			cred:   "AKID/20261015/us-east-1/s3/aws4_request",
			want:   credential{"AKID", "20261015", "us-east-1", "s3"},
			wantOK: true,
		},
		{
			// The parts are not validated here; the date is checked against
			// X-Amz-Date, and the key ID by the KeySource.
			cred:   "///x/aws4_request",
			want:   credential{"", "", "", "x"},
			wantOK: true,
		},
		{cred: ""},
		{cred: "AKID/20261015/us-east-1/s3"},
		{cred: "AKID/20261015/us-east-1/s3/aws4_request/"},
		{cred: "AKID/20261015/us-east-1/s3/AWS4_REQUEST"},
		{cred: "AK/ID/20261015/us-east-1/s3/aws4_request"},
	}
	for _, tt := range tests {
		t.Run(tt.cred, func(t *testing.T) {
			got, ok := parseCredential(tt.cred)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("got %+v, %v; want %+v, %v", got, ok, tt.want, tt.wantOK)
			}
			if ok && got.scope() != strings.SplitN(tt.cred, "/", 2)[1] {
				t.Fatalf("scope = %q", got.scope())
			}
		})
	}
}

func FuzzParseCredential(f *testing.F) {
	f.Add("AKID/20261015/us-east-1/s3/aws4_request")
	f.Add("a/b/c/d/e")
	f.Add("")
	f.Fuzz(func(t *testing.T, cred string) {
		got, ok := parseCredential(cred)
		parts := strings.Split(cred, "/")
		wantOK := len(parts) == 5 && parts[4] == scopeSuffix
		if ok != wantOK {
			t.Fatalf("%q: ok = %v, want %v", cred, ok, wantOK)
		}
		if !ok {
			return
		}
		if rebuilt := got.accessKeyID + "/" + got.scope(); rebuilt != cred {
			t.Fatalf("%q: rebuilt as %q", cred, rebuilt)
		}
	})
}

type presignCase struct {
	edit     func(url.Values)
	name     string
	wantKind Kind
}

func TestCheckPresignParams(t *testing.T) {
	full := url.Values{
		"X-Amz-Algorithm":     {algorithm},
		"X-Amz-Credential":    {"AKID/20261015/us-east-1/s3/aws4_request"},
		"X-Amz-Date":          {"20261015T120000Z"},
		"X-Amz-Expires":       {"3600"},
		"X-Amz-SignedHeaders": {"host"},
		"X-Amz-Signature":     {"abc"},
	}
	if err := checkPresignParams(full); err != nil {
		t.Fatalf("complete parameters: %v", err)
	}

	tests := make([]presignCase, 0, 2+2*len(presignParams))
	tests = append(tests, []presignCase{
		{
			name:     "another algorithm",
			edit:     func(q url.Values) { q.Set("X-Amz-Algorithm", "AWS4-HMAC-SHA1") },
			wantKind: KindUnsupportedAlgorithm,
		},
		{
			name:     "no algorithm",
			edit:     func(q url.Values) { q.Del("X-Amz-Algorithm") },
			wantKind: KindUnsupportedAlgorithm,
		},
	}...)
	for _, name := range presignParams {
		tests = append(
			tests,
			presignCase{
				name:     "no " + name,
				edit:     func(q url.Values) { q.Del(name) },
				wantKind: KindIncompleteAuth,
			},
		)
		tests = append(
			tests,
			presignCase{
				name:     "empty " + name,
				edit:     func(q url.Values) { q.Set(name, "") },
				wantKind: KindIncompleteAuth,
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := url.Values{}
			for k, v := range full {
				q[k] = append([]string(nil), v...)
			}
			tt.edit(q)
			err := checkPresignParams(q)
			if err == nil || err.Kind != tt.wantKind || !err.Presigned {
				t.Fatalf("err = %v, want presigned %s", err, tt.wantKind)
			}
		})
	}
}
