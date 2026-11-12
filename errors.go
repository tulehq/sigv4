package sigv4

import "strconv"

// Kind is the condition a request failed verification on. Each Kind is one
// condition, so a service can map it to the status and error code its
// protocol answers with; Error.Presigned and Error.Header carry the rest of
// what that mapping needs.
type Kind int

// The conditions a request can fail verification on, in roughly the order
// they are checked.
const (
	// KindMissingAuth: the request carries no Authorization header and, when
	// presigned URLs are accepted, no X-Amz-Algorithm query parameter.
	KindMissingAuth Kind = iota + 1

	// KindUnsupportedAlgorithm: the Authorization header, or the
	// X-Amz-Algorithm parameter of a presigned URL, names an algorithm other
	// than AWS4-HMAC-SHA256.
	KindUnsupportedAlgorithm

	// KindIncompleteAuth: the Authorization header lacks Credential,
	// SignedHeaders or Signature, or a presigned URL lacks one of its
	// X-Amz-* parameters.
	KindIncompleteAuth

	// KindInvalidDate: X-Amz-Date, the header or the presigned URL's
	// parameter, is missing or not in the ISO 8601 basic format.
	KindInvalidDate

	// KindRequestTimeTooSkewed: X-Amz-Date is further from the server's
	// clock than the allowed skew.
	KindRequestTimeTooSkewed

	// KindInvalidExpires: a presigned URL's X-Amz-Expires is not a number of
	// seconds within the allowed expiry.
	KindInvalidExpires

	// KindExpired: a presigned URL is past its X-Amz-Date plus X-Amz-Expires.
	KindExpired

	// KindMissingPayloadHash: with a streamed payload, an Authorization
	// header request carries no X-Amz-Content-Sha256 header.
	KindMissingPayloadHash

	// KindUnsignedHeader: the signature does not cover a header it must;
	// Error.Header names it.
	KindUnsignedHeader

	// KindMalformedCredential: the credential is not
	// <key>/<date>/<region>/<service>/aws4_request.
	KindMalformedCredential

	// KindUnknownAccessKey: the KeySource does not know the credential's
	// access key ID.
	KindUnknownAccessKey

	// KindKeyLookupFailed: the KeySource failed for another reason, or
	// returned an empty key; Error.Err holds its error, if any.
	KindKeyLookupFailed

	// KindCredentialDateMismatch: the credential's date is not the day of
	// X-Amz-Date.
	KindCredentialDateMismatch

	// KindWrongService: the credential is scoped to another service than
	// the one the verifier expects.
	KindWrongService

	// KindBodyUnreadable: with a buffered payload, reading the body failed;
	// Error.Err holds the read error.
	KindBodyUnreadable

	// KindBodyTooLarge: with a buffered payload, the body is larger than the
	// limit.
	KindBodyTooLarge

	// KindPayloadHashNotAccepted: X-Amz-Content-Sha256 is not a hex SHA-256
	// and not one of the values the verifier is configured to accept.
	KindPayloadHashNotAccepted

	// KindPayloadHashMismatch: X-Amz-Content-Sha256 is a hex SHA-256 that
	// does not match the body. With a streamed payload it is the error the
	// body's read fails with at EOF, not an error from Verify.
	KindPayloadHashMismatch

	// KindSignatureMismatch: the signature is not the one the request and
	// the signing key produce.
	KindSignatureMismatch
)

//nolint:gosec // G101: Kind names such as UnknownAccessKey, not credentials
var kindNames = [...]string{
	KindMissingAuth:            "MissingAuth",
	KindUnsupportedAlgorithm:   "UnsupportedAlgorithm",
	KindIncompleteAuth:         "IncompleteAuth",
	KindInvalidDate:            "InvalidDate",
	KindRequestTimeTooSkewed:   "RequestTimeTooSkewed",
	KindInvalidExpires:         "InvalidExpires",
	KindExpired:                "Expired",
	KindMissingPayloadHash:     "MissingPayloadHash",
	KindUnsignedHeader:         "UnsignedHeader",
	KindMalformedCredential:    "MalformedCredential",
	KindUnknownAccessKey:       "UnknownAccessKey",
	KindKeyLookupFailed:        "KeyLookupFailed",
	KindCredentialDateMismatch: "CredentialDateMismatch",
	KindWrongService:           "WrongService",
	KindBodyUnreadable:         "BodyUnreadable",
	KindBodyTooLarge:           "BodyTooLarge",
	KindPayloadHashNotAccepted: "PayloadHashNotAccepted",
	KindPayloadHashMismatch:    "PayloadHashMismatch",
	KindSignatureMismatch:      "SignatureMismatch",
}

func (k Kind) String() string {
	if k > 0 && int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "Kind(" + strconv.Itoa(int(k)) + ")"
}

// Error is a verification failure. Message is the text the Tule services
// send for it today; where they phrase a condition differently, the service
// substitutes its own (the README lists which).
type Error struct {
	// Err is the underlying error, for KindKeyLookupFailed and
	// KindBodyUnreadable. It is not meant for the client.
	Err error

	Message string

	// Header is the header the signature had to cover, for
	// KindUnsignedHeader.
	Header string

	Kind Kind

	// Presigned is set when the request was authenticated by a presigned
	// URL rather than an Authorization header.
	Presigned bool
}

func (e *Error) Error() string {
	return "sigv4: " + e.Kind.String() + ": " + e.Message
}

// Unwrap returns Err.
func (e *Error) Unwrap() error {
	return e.Err
}

func newError(kind Kind, presigned bool, msg string) *Error {
	return &Error{Kind: kind, Presigned: presigned, Message: msg}
}
