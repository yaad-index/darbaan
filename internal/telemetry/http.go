package telemetry

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"go.opentelemetry.io/otel/semconv/v1.41.0/httpconv"
)

// Handler records http.server.request.duration for every request next serves
// (ADR 0040 point 6). Its attributes are the method, the status code and the
// route template the ServeMux matched (`/queue/{id}`), never the path, the
// Host header or anything else the client sent. A request that matched no
// route has no http.route.
func (m *Metrics) Handler(next http.Handler) http.Handler {
	if m == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		attrs := []attribute.KeyValue{semconv.HTTPResponseStatusCode(sw.status)}
		// The ServeMux sets the pattern it matched on this same request.
		if route := routeOf(r.Pattern); route != "" {
			attrs = append(attrs, semconv.HTTPRoute(route))
		}
		if sw.status >= 500 {
			attrs = append(attrs, semconv.ErrorTypeKey.String(strconv.Itoa(sw.status)))
		}
		m.httpServer.Record(r.Context(), time.Since(start).Seconds(), method(r.Method), scheme, attrs...)
	})
}

// Transport records http.client.request.duration for every request base
// makes. Its attributes are the method, the status code or the failure's
// kind, and the host and port of the URL, which Darbaan's configuration names:
// never the path, which for some APIs carries a credential.
func (m *Metrics) Transport(base http.RoundTripper) http.RoundTripper {
	if m == nil {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripper(func(r *http.Request) (*http.Response, error) {
		start := time.Now()
		resp, err := base.RoundTrip(r)
		var attrs []attribute.KeyValue
		if err != nil {
			attrs = append(attrs, semconv.ErrorTypeKey.String(ErrorKind(err)))
		} else {
			attrs = append(attrs, semconv.HTTPResponseStatusCode(resp.StatusCode))
			if resp.StatusCode >= 500 {
				attrs = append(attrs, semconv.ErrorTypeKey.String(strconv.Itoa(resp.StatusCode)))
			}
		}
		m.httpClient.Record(r.Context(), time.Since(start).Seconds(), method(r.Method), r.URL.Hostname(), port(r), attrs...)
		return resp, err
	})
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// routeOf is the path template of a ServeMux pattern, without the method or
// host a pattern may start with: "GET /queue/{id}" is "/queue/{id}". The path
// is everything from the first slash, since neither a method nor a host can
// contain one.
func routeOf(pattern string) string {
	if i := strings.IndexByte(pattern, '/'); i >= 0 {
		return pattern[i:]
	}
	return ""
}

// method is the request method as the conventions name it: one of the
// standard methods, else _OTHER, so a client cannot invent a value.
func method(m string) httpconv.RequestMethodAttr {
	switch m {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return httpconv.RequestMethodAttr(m)
	}
	return httpconv.RequestMethodOther
}

// port is the URL's port, or the scheme's default.
func port(r *http.Request) int {
	if p := r.URL.Port(); p != "" {
		if n, err := strconv.Atoi(p); err == nil {
			return n
		}
	}
	if r.URL.Scheme == "https" {
		return 443
	}
	return 80
}
