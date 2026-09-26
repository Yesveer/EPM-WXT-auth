package metrics

import (
	"runtime"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	HTTPRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_auth_http_requests_total",
		Help: "Total number of HTTP requests",
	}, []string{"method", "path", "status_code"})

	HTTPRequestDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "vsay_auth_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "path"})

	HTTPRequestsInFlight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "vsay_auth_http_requests_in_flight",
		Help: "Current number of HTTP requests being processed",
	})

	LoginAttemptsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_auth_login_attempts_total",
		Help: "Total login attempts by status and provider",
	}, []string{"status", "provider"})

	JWTValidationsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "vsay_auth_jwt_validations_total",
		Help: "Total JWT validation attempts",
	}, []string{"result"})

	BuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "vsay_auth_build_info",
		Help: "Build information",
	}, []string{"service", "goversion"})
)

func init() {
	BuildInfo.WithLabelValues("vsay-auth", runtime.Version()).Set(1)
}
