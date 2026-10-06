package telemetry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-smtp"
)

// The kinds an upstream failure is counted by, the values of error.type (ADR
// 0040 point 5). Each is decided from the error's type, never its text.
const (
	// KindDial is a connection that could not be opened.
	KindDial = "dial"
	// KindTLS is a failed TLS handshake or certificate check.
	KindTLS = "tls"
	// KindAuth is a login the server refused, as an IMAP server reports it.
	KindAuth = "auth"
	// KindTimeout is a deadline that passed.
	KindTimeout = "timeout"
	// KindCanceled is a cancellation, as at shutdown.
	KindCanceled = "canceled"
	// KindProtocol is any other IMAP status the server answered with.
	KindProtocol = "protocol"
	// Kind4xx and Kind5xx are SMTP replies, by class only: never the reply's
	// text or its enhanced code.
	Kind4xx = "4xx"
	Kind5xx = "5xx"
	// KindOther is every failure of a kind not named here.
	KindOther = "_OTHER"
)

// ErrorKind is the kind of an upstream SMTP or IMAP failure.
func ErrorKind(err error) string {
	var se *smtp.SMTPError
	var ie *imap.Error
	var opErr *net.OpError
	var netErr net.Error
	var certErr *tls.CertificateVerificationError
	var alertErr tls.AlertError
	var recErr tls.RecordHeaderError
	var unknownCA x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var invalidCert x509.CertificateInvalidError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return KindTimeout
	case errors.Is(err, context.Canceled):
		return KindCanceled
	case errors.As(err, &se):
		if se.Code >= 500 {
			return Kind5xx
		}
		return Kind4xx
	case errors.As(err, &ie):
		if ie.Code == imap.ResponseCodeAuthenticationFailed || ie.Code == imap.ResponseCodeAuthorizationFailed {
			return KindAuth
		}
		return KindProtocol
	case errors.As(err, &certErr), errors.As(err, &alertErr), errors.As(err, &recErr),
		errors.As(err, &unknownCA), errors.As(err, &hostErr), errors.As(err, &invalidCert):
		return KindTLS
	case errors.As(err, &opErr) && opErr.Op == "dial":
		return KindDial
	case errors.As(err, &netErr) && netErr.Timeout():
		return KindTimeout
	}
	return KindOther
}
