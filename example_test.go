package sigv4_test

import (
	"errors"
	"log"
	"net/http"

	"tule.dev/sigv4"
)

// apiError stands in for a service's own wire error type.
type apiError struct {
	Type    string
	Message string
	Status  int
}

func (e *apiError) Error() string { return e.Type + ": " + e.Message }

// jsonError maps a verification failure to an AWS JSON error.
func jsonError(e *sigv4.Error) error {
	switch e.Kind {
	case sigv4.KindMissingAuth:
		return &apiError{"MissingAuthenticationTokenException", e.Message, 403}
	case sigv4.KindUnknownAccessKey:
		return &apiError{"UnrecognizedClientException", e.Message, 403}
	case sigv4.KindRequestTimeTooSkewed, sigv4.KindSignatureMismatch:
		return &apiError{"InvalidSignatureException", e.Message, 403}
	case sigv4.KindPayloadHashMismatch, sigv4.KindBodyUnreadable:
		return &apiError{"InvalidParameterException", e.Message, 400}
	case sigv4.KindBodyTooLarge:
		return &apiError{"InvalidParameterException", e.Message, 413}
	case sigv4.KindKeyLookupFailed:
		return &apiError{"InternalServiceError", "An error occurred on the server side.", 500}
	default:
		return &apiError{"IncompleteSignatureException", e.Message, 403}
	}
}

// verifySignature answers a request whose signature does not verify with
// the error v's map made of it.
func verifySignature(v *sigv4.Verifier, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := v.Verify(r); err != nil {
			var apiErr *apiError
			if !errors.As(err, &apiErr) {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			http.Error(w, apiErr.Message, apiErr.Status)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// An AWS JSON service: the defaults, plus X-Amz-Target among the headers the
// signature must cover, since it names the operation.
func ExampleNew_json() {
	v, err := sigv4.New(
		sigv4.NewStaticKey("AKIDEXAMPLE", "secret"),
		sigv4.WithRequiredSignedHeaders("host", "x-amz-date", "x-amz-target"),
		sigv4.WithErrorMap(jsonError),
	)
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", verifySignature(v, http.NotFoundHandler()))
}

// An S3 service: presigned URLs, a streamed payload checked against the
// declared hash as the handler reads it, and any declared hash accepted.
func ExampleNew_s3() {
	v, err := sigv4.New(
		sigv4.NewStaticKey("AKIDEXAMPLE", "secret"),
		sigv4.WithPresignedURLs(true),
		sigv4.WithStreamedPayload(),
		sigv4.WithAnyPayloadHash(true),
		sigv4.WithRequiredSignedHeaders(),
		sigv4.WithErrorMap(func(e *sigv4.Error) error {
			// The map applies to the body's read too, so an upload whose body
			// does not match its hash fails with the service's own error.
			if e.Kind == sigv4.KindPayloadHashMismatch {
				return &apiError{"XAmzContentSHA256Mismatch", e.Message, 400}
			}
			return &apiError{"AccessDenied", e.Message, 403}
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	http.Handle("/", verifySignature(v, http.NotFoundHandler()))
}
