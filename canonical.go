package sigv4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// signature computes the signature r should carry for the claims in s, with
// uri its canonical URI.
func signature(r *http.Request, s *signed, uri string) string {
	creq := strings.Join([]string{
		r.Method,
		uri,
		canonicalQuery(r.URL.Query(), s.presigned),
		canonicalHeaders(r, s.signedHeaders),
		strings.Join(s.signedHeaders, ";"),
		s.payloadHash,
	}, "\n")

	creqHash := sha256.Sum256([]byte(creq))
	toSign := strings.Join([]string{
		algorithm,
		s.date.Format(amzDateFmt),
		s.cred.scope(),
		hex.EncodeToString(creqHash[:]),
	}, "\n")

	return hex.EncodeToString(hmacSHA256(s.key.Signing, toSign))
}

// canonicalURI is the path as the client sent it, URI-encoded once more for
// every service but S3, as SigV4 specifies and the SDK signs: the path sent,
// already encoded once by the client, has each byte outside the unreserved
// set, '%' among them, encoded again. For S3, which signs the path encoded
// once (s3 set), each segment is decoded and re-encoded instead.
//
// Either way an encoded slash, %2F, stays part of its segment, since the path
// is taken as sent, not decoded: a signature over /bucket/a/b does not cover
// /bucket/a%2Fb, which a server may read as another key.
//
// The path sent is RawPath whenever it is set and decodes to Path, even when
// it is not encoded as URL.EscapedPath requires: for /b/a%2Fb{, EscapedPath
// escapes the decoded Path instead, /b/a/b%7B, and would lose the encoded
// slash. A RawPath that does not decode to Path, which only a middleware
// rewriting one and not the other leaves, reports false.
func canonicalURI(u *url.URL, s3 bool) (string, bool) {
	p := u.EscapedPath()
	if u.RawPath != "" {
		if dec, err := url.PathUnescape(u.RawPath); err != nil || dec != u.Path {
			return "", false
		}
		p = u.RawPath
	}
	if p == "" {
		return "/", true
	}
	if !s3 {
		return uriEncode(p, false), true
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		dec, err := url.PathUnescape(seg)
		if err != nil {
			// The whole path decoded above, so a segment does; were it not,
			// encoding it as is gives a path no signer produced.
			dec = seg
		}
		segs[i] = uriEncode(dec, true)
	}
	return strings.Join(segs, "/"), true
}

// canonicalQuery URI-encodes the query's names and values and sorts it by
// encoded name, then by encoded value, as the SDK signer does. Sorting the
// joined "name=value" strings would put "a-b=2" before "a=1". A presigned
// URL's own signature is not part of what it signs.
func canonicalQuery(q url.Values, presigned bool) string {
	type param struct{ key, value string }
	var params []param
	for k, vals := range q {
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		key := uriEncode(k, true)
		for _, val := range vals {
			params = append(params, param{key: key, value: uriEncode(val, true)})
		}
	}
	slices.SortFunc(params, func(a, b param) int {
		if c := strings.Compare(a.key, b.key); c != 0 {
			return c
		}
		return strings.Compare(a.value, b.value)
	})

	var sb strings.Builder
	for i, p := range params {
		if i > 0 {
			sb.WriteByte('&')
		}
		sb.WriteString(p.key)
		sb.WriteByte('=')
		sb.WriteString(p.value)
	}
	return sb.String()
}

// canonicalHeaders lists the signed headers as "name:value\n" lines, each
// value as canonicalValue makes it.
//
// The values are collapsed in place, in r.Header itself, so the handler sees
// a signed header as it was signed. Every copy this package replaces did
// this, and a service may store what it reads (S3 user metadata, for one),
// so it is kept rather than changing what clients read back.
func canonicalHeaders(r *http.Request, names []string) string {
	var sb strings.Builder
	for _, name := range names {
		var val string
		switch vals := r.Header.Values(name); {
		case name == "host":
			val = r.Host
		case name == "content-length" && len(vals) == 0 && r.ContentLength >= 0:
			// net/http may keep the length only in r.ContentLength.
			val = strconv.FormatInt(r.ContentLength, 10)
		default:
			for i, x := range vals {
				vals[i] = canonicalValue(x)
			}
			val = strings.Join(vals, ",")
		}
		sb.WriteString(name)
		sb.WriteByte(':')
		sb.WriteString(val)
		sb.WriteByte('\n')
	}
	return sb.String()
}

// canonicalValue is a header value as the SDK signer canonicalizes it: runs
// of spaces collapsed to one, then leading and trailing whitespace trimmed.
// Only spaces are collapsed; a tab inside the value is kept.
func canonicalValue(v string) string {
	var sb strings.Builder
	sb.Grow(len(v))
	for i := range len(v) {
		if v[i] == ' ' && i > 0 && v[i-1] == ' ' {
			continue
		}
		sb.WriteByte(v[i])
	}
	return strings.TrimSpace(sb.String())
}

// uriEncode percent-encodes everything but the RFC 3986 unreserved characters,
// and slashes unless encodeSlash is set.
func uriEncode(s string, encodeSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var sb strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			c == '-', c == '_', c == '.', c == '~',
			c == '/' && !encodeSlash:
			sb.WriteByte(c)
		default:
			sb.WriteByte('%')
			sb.WriteByte(hexDigits[c>>4])
			sb.WriteByte(hexDigits[c&0xf])
		}
	}
	return sb.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func isHexSHA256(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
