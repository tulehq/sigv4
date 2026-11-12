package sigv4

import (
	"net/url"
	"strconv"
	"strings"
)

// authHeader is what a SigV4 Authorization header carries.
type authHeader struct {
	credential    string
	signedHeaders string
	signature     string
}

// parseAuthorization parses the Credential, SignedHeaders and Signature
// fields of a SigV4 Authorization header. A field given twice keeps its last
// value, and fields other than those three are ignored.
func parseAuthorization(auth string) (authHeader, *Error) {
	var h authHeader
	fields, ok := strings.CutPrefix(auth, algorithm+" ")
	if !ok {
		return h, newError(KindUnsupportedAlgorithm, false, "The authorization mechanism you "+
			"have provided is not supported. Please use "+algorithm+".")
	}

	for f := range strings.SplitSeq(fields, ",") {
		k, val, _ := strings.Cut(strings.TrimSpace(f), "=")
		switch k {
		case "Credential":
			h.credential = val
		case "SignedHeaders":
			h.signedHeaders = val
		case "Signature":
			h.signature = val
		}
	}
	if h.credential == "" || h.signedHeaders == "" || h.signature == "" {
		return h, newError(KindIncompleteAuth, false, "The authorization header is malformed; "+
			"it must contain Credential, SignedHeaders and Signature.")
	}
	return h, nil
}

// MaxSignedHeaders is the most headers a SignedHeaders list may name. The
// SDK signs every header it sends, a dozen or two; the bound keeps the
// canonical request small whatever a client claims.
const MaxSignedHeaders = 128

// parseSignedHeaders splits a SignedHeaders list, reporting false unless it
// is as SigV4 specifies it: lowercase header names, sorted and unique, with
// no spaces or empty entries, and at most MaxSignedHeaders of them. Each
// header is then canonicalized once, so the canonical request is no larger
// than the headers it covers, and the required-header check matches the
// names exactly as they are signed.
func parseSignedHeaders(list string) ([]string, bool) {
	names := strings.Split(list, ";")
	if len(names) > MaxSignedHeaders {
		return nil, false
	}
	for i, name := range names {
		if !isLowerToken(name) || (i > 0 && names[i-1] >= name) {
			return nil, false
		}
	}
	return names, true
}

// isLowerToken reports whether s is a non-empty HTTP field name in
// lowercase.
func isLowerToken(s string) bool {
	if s == "" {
		return false
	}
	for i := range len(s) {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9',
			strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

func malformedSignedHeaders(presigned bool) *Error {
	return newError(KindIncompleteAuth, presigned, "The SignedHeaders list is malformed; it "+
		"must name lowercase headers, sorted and unique, and at most "+
		strconv.Itoa(MaxSignedHeaders)+" of them.")
}

// presignParams are the query parameters a presigned URL must carry.
var presignParams = []string{
	"X-Amz-Credential", "X-Amz-Date", "X-Amz-Expires", "X-Amz-SignedHeaders", "X-Amz-Signature",
}

// checkPresignParams checks that a presigned URL carries every SigV4 query
// parameter.
func checkPresignParams(q url.Values) *Error {
	if q.Get("X-Amz-Algorithm") != algorithm {
		return newError(KindUnsupportedAlgorithm, true,
			"X-Amz-Algorithm only supports \""+algorithm+"\"")
	}
	for _, name := range presignParams {
		if q.Get(name) == "" {
			return newError(KindIncompleteAuth, true, "Query-string authentication version 4 "+
				"requires the X-Amz-Algorithm, X-Amz-Credential, X-Amz-Signature, X-Amz-Date, "+
				"X-Amz-SignedHeaders, and X-Amz-Expires parameters.")
		}
	}
	return nil
}

// credential is a parsed "<key>/<date>/<region>/<service>/aws4_request".
type credential struct {
	accessKeyID string
	date        string
	region      string
	service     string
}

// scope is the credential scope the string to sign carries.
func (c credential) scope() string {
	return c.date + "/" + c.region + "/" + c.service + "/" + scopeSuffix
}

// parseCredential splits a credential into its parts, reporting false when it
// does not have five of them ending in aws4_request.
func parseCredential(cred string) (credential, bool) {
	parts := strings.Split(cred, "/")
	if len(parts) != 5 || parts[4] != scopeSuffix {
		return credential{}, false
	}
	return credential{
		accessKeyID: parts[0],
		date:        parts[1],
		region:      parts[2],
		service:     parts[3],
	}, true
}
