package sigv4

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"net/http"
	"strings"
)

const (
	unsignedPayload  = "UNSIGNED-PAYLOAD"
	streamingPrefix  = "STREAMING-"
	hashMismatchText = "The provided 'x-amz-content-sha256' header does not match what was computed."
)

// bufferPayload reads the body, checks the declared payload hash against it
// and, when none was declared, signs the body's own hash. It returns the body
// for the handler to read in place of r.Body.
func (v *Verifier) bufferPayload(r *http.Request, s *signed) ([]byte, *Error) {
	body, err := v.readBody(r, s.presigned)
	if err != nil {
		return nil, err
	}

	sum := sha256.Sum256(body)
	bodyHash := hex.EncodeToString(sum[:])
	switch {
	case s.payloadHash == "":
		// The SDKs sign the hash without sending it, which is the usual case:
		// the body's own hash goes into the canonical request, so a body that
		// was changed in flight fails the signature.
		s.payloadHash = bodyHash
		s.bodyCovered = true
	case !isHexSHA256(s.payloadHash):
		// An accepted opaque hash is signed as sent; the body is not.
		if err = v.checkOpaqueHash(s); err != nil {
			return nil, err
		}
	case !strings.EqualFold(s.payloadHash, bodyHash):
		return nil, newError(KindPayloadHashMismatch, s.presigned, hashMismatchText)
	default:
		s.bodyCovered = true
	}
	return body, nil
}

// readBody reads up to the body limit of r's body, rejecting anything longer
// rather than verifying a signature over a truncated body.
func (v *Verifier) readBody(r *http.Request, presigned bool) ([]byte, *Error) {
	if r.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, v.maxBody+1))
	if err != nil {
		e := newError(KindBodyUnreadable, presigned, "The request body could not be read.")
		e.Err = err
		return nil, e
	}
	if int64(len(body)) > v.maxBody {
		return nil, newError(KindBodyTooLarge, presigned,
			"The request body is larger than this service accepts.")
	}
	return body, nil
}

// checkOpaqueHash refuses a declared payload hash that is not a hex SHA-256
// unless the verifier accepts it. Accepting UNSIGNED-PAYLOAD asks for a
// signature that covers no part of the body, which lets whoever relays a
// signed request swap the body for another operation's.
func (v *Verifier) checkOpaqueHash(s *signed) *Error {
	const prefix = "x-amz-content-sha256 must be the hex SHA-256 of the request body"

	streaming := strings.HasPrefix(s.payloadHash, streamingPrefix)
	switch {
	case v.allowAnyHash,
		s.payloadHash == unsignedPayload && v.allowUnsigned,
		streaming && v.allowStreaming:
		return nil
	case !v.allowUnsigned:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+"; "+unsignedPayload+" is not accepted.")
	case streaming:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+" or "+unsignedPayload+"; "+streamingPrefix+"* payloads are not accepted.")
	default:
		return newError(KindPayloadHashNotAccepted, s.presigned,
			prefix+" or "+unsignedPayload+".")
	}
}

// replaceBody hands the handler the body the signature covers: the buffered
// bytes, or with a streamed payload and a hex hash, a reader that checks the
// body against it.
func (v *Verifier) replaceBody(r *http.Request, s *signed, buffered []byte) {
	switch {
	case !v.streamed:
		r.Body = &bufferedBody{
			Reader:    bytes.NewReader(buffered),
			covered:   s.bodyCovered,
			presigned: s.presigned,
		}
	case isHexSHA256(s.payloadHash) && r.Body != nil:
		r.Body = &payloadVerifier{
			body:      r.Body,
			h:         sha256.New(),
			want:      s.payloadHash,
			mapErr:    v.mapError,
			length:    r.ContentLength,
			presigned: s.presigned,
		}
	}
}

// bufferedBody is a buffered payload. covered is set when the signature
// covers its bytes, and not when they were sent under an opaque payload
// hash, which signs no part of them.
type bufferedBody struct {
	*bytes.Reader
	covered   bool
	presigned bool
}

func (*bufferedBody) Close() error { return nil }

// ReadBody reads the whole body of r, a request Verify returned, up to max
// bytes, and returns it only once it is verified against the signature. It
// is for handlers that act on a small body, such as an S3 DeleteObjects or
// CompleteMultipartUpload document, and would otherwise decode it with a
// reader that stops at the end of its value, before the body's hash is
// checked.
//
// It takes the body Verify set. A body a middleware wrapped after Verify,
// such as an http.MaxBytesReader, can no longer be told verified and is
// refused with KindUnverifiedPayload, so Verify should sit innermost, after
// any middleware that wraps the body; ReadBody's own limit stands in for a
// MaxBytesReader.
//
// It fails, through the WithErrorMap function, with KindBodyTooLarge for a
// body over max, KindPayloadHashMismatch for one that does not match its
// declared hash, and KindUnverifiedPayload for one no hash covers: a body
// sent under UNSIGNED-PAYLOAD, a STREAMING-* value or any other opaque hash
// the verifier accepts, in either payload mode. A read error of the body itself is returned as
// is.
func (v *Verifier) ReadBody(r *http.Request, maxBytes int64) ([]byte, error) {
	var presigned bool
	switch b := r.Body.(type) {
	case *payloadVerifier:
		// Wrapped only under a hex hash, which its reads check.
		presigned = b.presigned
	case *bufferedBody:
		if !b.covered {
			return nil, v.mapError(newError(KindUnverifiedPayload, b.presigned,
				"The request body is not covered by the signature."))
		}
		presigned = b.presigned
	default:
		return nil, v.mapError(newError(KindUnverifiedPayload, false,
			"The request body is not covered by the signature."))
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, err //nolint:wrapcheck // a verification failure is already mapped
	}
	if int64(len(body)) > maxBytes {
		return nil, v.mapError(newError(KindBodyTooLarge, presigned,
			"The request body is larger than this service accepts."))
	}
	return body, nil
}

// payloadVerifier checks a streamed body against its declared SHA-256 and
// fails the read where the body is found not to match it, so an upload
// reading it is not committed.
//
// With a known Content-Length the hash is checked on the read that reaches
// that many bytes, so a handler that reads exactly Content-Length bytes and
// stops, as io.ReadFull, io.LimitReader and http.MaxBytesReader do, still
// sees the failure. A read past Content-Length fails, and so does an EOF
// short of it. With an unknown length, the read that reaches EOF is checked.
//
// A handler that stops earlier, as a decoder does at the end of its value,
// never reaches the check on its reads. Close then reads what it left, as
// net/http does an unread body: at most maxDrain, and with a known length,
// nothing when more than that is left. It fails with a mismatch when the
// body read to its end does not match, and with KindUnverifiedPayload when
// the body was not read to its end, so a large or slow body does not hold
// the handler.
//
// A failing read returns no bytes: io.ReadFull drops an error that comes
// with a full buffer, so a read that filled it would hide the failure.
type payloadVerifier struct {
	body      io.ReadCloser
	h         hash.Hash
	failed    error // the first failure, which every later read returns
	closeErr  error // what the first Close returned
	mapErr    func(*Error) error
	want      string
	length    int64 // Content-Length, or -1 when unknown
	n         int64 // bytes read so far
	verified  bool  // the whole body was read and matched
	closed    bool
	presigned bool
}

// maxDrain is the most Close reads of what a handler left of a body: the
// 256 KiB net/http reads of an unread body before it closes the connection
// instead (maxPostHandlerReadBytes in net/http's server).
const maxDrain = 256 << 10

func (p *payloadVerifier) Read(b []byte) (int, error) {
	if p.failed != nil {
		return 0, p.failed
	}
	n, err := p.body.Read(b)
	if p.length >= 0 && p.n+int64(n) > p.length {
		// The body runs past Content-Length, which the hash does not cover.
		p.n = p.length
		p.verified = false
		return 0, p.mismatch()
	}
	p.h.Write(b[:n])
	p.n += int64(n)
	if !p.valid(errors.Is(err, io.EOF)) {
		return 0, p.mismatch()
	}
	return n, err //nolint:wrapcheck // io.Reader contract: EOF must pass through unwrapped
}

// valid reports whether the body read so far may be handed over: it is
// checked once it reaches Content-Length, or at EOF when its length is
// unknown, and an EOF short of a known length fails.
func (p *payloadVerifier) valid(eof bool) bool {
	known := p.length >= 0
	switch {
	case p.verified:
		return true
	case known && p.n == p.length, !known && eof:
		p.verified = p.matches()
		return p.verified
	case eof:
		return false
	default:
		return true
	}
}

func (p *payloadVerifier) matches() bool {
	return strings.EqualFold(hex.EncodeToString(p.h.Sum(nil)), p.want)
}

// mismatch records the body's failure, so every later read returns it too.
func (p *payloadVerifier) mismatch() error {
	p.failed = p.mapErr(newError(KindPayloadHashMismatch, p.presigned, hashMismatchText))
	return p.failed
}

// Close reads what the handler left of the body and fails if the body does
// not match its hash, then closes it. A second Close returns what the first
// did, without reading the closed body again.
func (p *payloadVerifier) Close() error {
	if p.closed {
		return p.closeErr
	}
	p.closed = true
	p.closeErr = p.finish()
	if cerr := p.body.Close(); p.closeErr == nil {
		p.closeErr = cerr
	}
	return p.closeErr //nolint:wrapcheck // a mismatch is already mapped; a close error passes through
}

// finish reads the rest of the body through Read, so it is checked, and
// reports a body that does not match or was not read to its end.
func (p *payloadVerifier) finish() error {
	if p.failed != nil {
		return p.failed
	}
	limit := int64(maxDrain)
	if p.length >= 0 {
		left := p.length - p.n
		if left > maxDrain {
			return p.unverified()
		}
		// One byte past Content-Length, to catch a body that runs on.
		limit = left + 1
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(p, limit)); err != nil {
		return err //nolint:wrapcheck // a mismatch is already mapped; a read error passes through
	}
	if !p.verified {
		return p.unverified()
	}
	return nil
}

// unverified records that the body was not read to its end, so it was
// never checked.
func (p *payloadVerifier) unverified() error {
	p.failed = p.mapErr(newError(KindUnverifiedPayload, p.presigned,
		"The request body was not read to its end, so it is not verified."))
	return p.failed
}
