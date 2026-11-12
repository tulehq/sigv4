package sigv4

import (
	"net/url"
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
