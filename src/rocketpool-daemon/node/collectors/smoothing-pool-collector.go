package collectors

import (
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rocket-pool/node-manager-core/eth"
	"github.com/rocket-pool/node-manager-core/log"
	"github.com/rocket-pool/smartnode/rocketpool-daemon/common/services"
	"github.com/rocket-pool/smartnode/shared/keys"
)

// Represents the collector for Smoothing Pool metrics
type SmoothingPoolCollector struct {
	// the ETH balance on the smoothing pool
	ethBalanceOnSmoothingPool *prometheus.Desc

	// The Smartnode service provider
	sp *services.ServiceProvider

	// The logger
	logger *slog.Logger

	// The thread-safe locker for the network state
	stateLocker *StateLocker
}

// Create a new SmoothingPoolCollector instance
func NewSmoothingPoolCollector(logger *log.Logger, sp *services.ServiceProvider, stateLocker *StateLocker) *SmoothingPoolCollector {
	subsystem := "smoothing_pool"
	sublogger := logger.With(slog.String(keys.RoutineKey, "SP Collector"))
	return &SmoothingPoolCollector{
		ethBalanceOnSmoothingPool: prometheus.NewDesc(prometheus.BuildFQName(namespace, subsystem, "eth_balance"),
			"The ETH balance on the smoothing pool",
			nil, nil,
		),
		sp:          sp,
		logger:      sublogger,
		stateLocker: stateLocker,
	}
}

// Write metric descriptions to the Prometheus channel
func (collector *SmoothingPoolCollector) Describe(channel chan<- *prometheus.Desc) {
	channel <- collector.ethBalanceOnSmoothingPool
}

// Collect the latest metric values and pass them to Prometheus
func (collector *SmoothingPoolCollector) Collect(channel chan<- prometheus.Metric) {
	// Get the latest state
	state := collector.stateLocker.GetState()
	if state == nil {
		return
	}

	ethBalanceOnSmoothingPool := eth.WeiToEth(state.NetworkDetails.SmoothingPoolBalance)

	channel <- prometheus.MustNewConstMetric(
		collector.ethBalanceOnSmoothingPool, prometheus.GaugeValue, ethBalanceOnSmoothingPool)
}
