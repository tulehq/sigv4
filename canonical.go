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

// signature computes the signature r should carry for the claims in s.
func signature(r *http.Request, s *signed) string {
	creq := strings.Join([]string{
		r.Method,
		canonicalURI(r.URL.Path),
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

	return hex.EncodeToString(hmacSHA256(s.key, toSign))
}

func canonicalURI(p string) string {
	if p == "" {
		return "/"
	}
	return uriEncode(p, false)
}

// canonicalQuery sorts the query by name and then value, URI-encoding both.
// A presigned URL's own signature is not part of what it signs.
func canonicalQuery(q url.Values, presigned bool) string {
	var pairs []string
	for k, vals := range q {
		if presigned && k == "X-Amz-Signature" {
			continue
		}
		for _, val := range vals {
			pairs = append(pairs, uriEncode(k, true)+"="+uriEncode(val, true))
		}
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "&")
}

// canonicalHeaders lists the signed headers as "name:value\n" lines, with
// values trimmed and inner runs of spaces collapsed.
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
				vals[i] = strings.Join(strings.Fields(x), " ")
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
