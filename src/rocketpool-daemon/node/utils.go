package node

import (
	"math/big"

	"github.com/rocket-pool/node-manager-core/eth"
	"github.com/rocket-pool/node-manager-core/log"
	"github.com/rocket-pool/smartnode/shared/config"
)

func getAutoTxInfo(cfg *config.SmartNodeConfig, logger **log.Logger) (*big.Int, *big.Int) {
	// Get the user-requested max fee
	maxFeeGwei := cfg.AutoTxMaxFee.Value
	var maxFee *big.Int
	if maxFeeGwei == 0 {
		maxFee = nil
	} else {
		maxFee = eth.GweiToWei(maxFeeGwei)
	}

	// Get the user-requested max fee
	priorityFeeGwei := cfg.MaxPriorityFee.Value
	var priorityFee *big.Int
	if priorityFeeGwei == 0 {
		logger.Println("WARNING: priority fee was missing or 0, setting a default of 2.")
		priorityFee = eth.GweiToWei(2)
	} else {
		priorityFee = eth.GweiToWei(priorityFeeGwei)
	}

	return maxFee, priorityFee
}
