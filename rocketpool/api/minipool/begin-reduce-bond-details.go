package minipool

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	batch "github.com/rocket-pool/batch-query"
	"github.com/rocket-pool/rocketpool-go/core"
	"github.com/rocket-pool/rocketpool-go/dao/oracle"
	"github.com/rocket-pool/rocketpool-go/dao/protocol"
	"github.com/rocket-pool/rocketpool-go/minipool"
	"github.com/rocket-pool/rocketpool-go/node"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/rocket-pool/rocketpool-go/types"
	"github.com/rocket-pool/smartnode/rocketpool/common/beacon"
	"github.com/rocket-pool/smartnode/rocketpool/common/server"
	sharedtypes "github.com/rocket-pool/smartnode/shared/types"
	"github.com/rocket-pool/smartnode/shared/types/api"
)

// ===============
// === Factory ===
// ===============

type minipoolBeginReduceBondDetailsContextFactory struct {
	handler *MinipoolHandler
}

func (f *minipoolBeginReduceBondDetailsContextFactory) Create(args url.Values) (*minipoolBeginReduceBondDetailsContext, error) {
	c := &minipoolBeginReduceBondDetailsContext{
		handler: f.handler,
	}
	return c, nil
}

func (f *minipoolBeginReduceBondDetailsContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterMinipoolRoute[*minipoolBeginReduceBondDetailsContext, api.MinipoolBeginReduceBondDetailsData](
		router, "begin-reduce-bond/details", f, f.handler.serviceProvider,
	)
}

// ===============
// === Context ===
// ===============

type minipoolBeginReduceBondDetailsContext struct {
	handler *MinipoolHandler
	rp      *rocketpool.RocketPool
	bc      beacon.Client

	newBondAmountWei *big.Int
	node             *node.Node
	pSettings        *protocol.ProtocolDaoSettings
	oSettings        *oracle.OracleDaoSettings
}

func (c *minipoolBeginReduceBondDetailsContext) Initialize() error {
	sp := c.handler.serviceProvider
	c.rp = sp.GetRocketPool()
	c.bc = sp.GetBeaconClient()
	nodeAddress, _ := sp.GetWallet().GetAddress()

	// Requirements
	err := errors.Join(
		sp.RequireNodeRegistered(),
	)
	if err != nil {
		return err
	}

	// Bindings
	c.node, err = node.NewNode(c.rp, nodeAddress)
	if err != nil {
		return fmt.Errorf("error creating node binding: %w", err)
	}
	pMgr, err := protocol.NewProtocolDaoManager(c.rp)
	if err != nil {
		return fmt.Errorf("error creating pDAO manager binding: %w", err)
	}
	c.pSettings = pMgr.Settings
	oMgr, err := oracle.NewOracleDaoManager(c.rp)
	if err != nil {
		return fmt.Errorf("error creating oDAO manager binding: %w", err)
	}
	c.oSettings = oMgr.Settings
	return nil
}

func (c *minipoolBeginReduceBondDetailsContext) GetState(node *node.Node, mc *batch.MultiCaller) {
	core.AddQueryablesToMulticall(mc,
		c.node.IsFeeDistributorInitialized,
		c.pSettings.Minipool.IsBondReductionEnabled,
		c.oSettings.Minipool.BondReductionWindowStart,
		c.oSettings.Minipool.BondReductionWindowLength,
	)
}

func (c *minipoolBeginReduceBondDetailsContext) CheckState(node *node.Node, data *api.MinipoolBeginReduceBondDetailsData) bool {
	data.BondReductionDisabled = !c.pSettings.Minipool.IsBondReductionEnabled.Get()
	return !data.BondReductionDisabled
}

func (c *minipoolBeginReduceBondDetailsContext) GetMinipoolDetails(mc *batch.MultiCaller, mp minipool.IMinipool, index int) {
	mpCommon := mp.Common()
	core.AddQueryablesToMulticall(mc,
		mpCommon.NodeDepositBalance,
		mpCommon.NodeFee,
	)
	mpv3, success := minipool.GetMinipoolAsV3(mp)
	if success {
		core.AddQueryablesToMulticall(mc,
			mpv3.NodeDepositBalance,
			mpv3.IsFinalised,
			mpv3.Status,
			mpv3.Pubkey,
			mpv3.ReduceBondTime,
			mpv3.IsBondReduceCancelled,
		)
	}
}

func (c *minipoolBeginReduceBondDetailsContext) PrepareData(addresses []common.Address, mps []minipool.IMinipool, data *api.MinipoolBeginReduceBondDetailsData) error {
	// General vars
	data.IsFeeDistributorInitialized = c.node.IsFeeDistributorInitialized.Get()
	data.BondReductionWindowStart = c.oSettings.Minipool.BondReductionWindowStart.Formatted()
	data.BondReductionWindowLength = c.oSettings.Minipool.BondReductionWindowLength.Formatted()

	// Get the latest block header
	header, err := c.rp.Client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("error getting latest block header: %w", err)
	}
	currentTime := time.Unix(int64(header.Time), 0)

	// Get the bond reduction details
	pubkeys := []types.ValidatorPubkey{}
	detailsMap := map[types.ValidatorPubkey]int{}
	details := make([]api.MinipoolBeginReduceBondDetails, len(addresses))
	for i, mp := range mps {
		details[i] = c.getMinipoolDetails(mp, currentTime)
		pubkey := mp.Common().Pubkey.Get()
		pubkeys = append(pubkeys, pubkey)
		detailsMap[pubkey] = i
	}

	// Get the statuses on Beacon
	beaconStatuses, err := c.bc.GetValidatorStatuses(pubkeys, nil)
	if err != nil {
		return fmt.Errorf("error getting validator statuses on Beacon: %w", err)
	}

	// Do a complete viability check
	for pubkey, beaconStatus := range beaconStatuses {
		i := detailsMap[pubkey]
		mpDetails := &details[i]
		mpDetails.Balance = beaconStatus.Balance
		mpDetails.BeaconState = beaconStatus.Status

		// Check the beacon state
		mpDetails.InvalidBeaconState = !(mpDetails.BeaconState == sharedtypes.ValidatorState_PendingInitialized ||
			mpDetails.BeaconState == sharedtypes.ValidatorState_PendingQueued ||
			mpDetails.BeaconState == sharedtypes.ValidatorState_ActiveOngoing)

		// Make sure the balance is high enough
		threshold := uint64(32000000000)
		mpDetails.BalanceTooLow = mpDetails.Balance < threshold

		mpDetails.CanReduce = !(data.BondReductionDisabled || mpDetails.MinipoolVersionTooLow || mpDetails.AlreadyInWindow || mpDetails.BalanceTooLow || mpDetails.InvalidBeaconState || mpDetails.AlreadyCancelled || mpDetails.NodeDepositTooLow)
	}

	data.Details = details
	return nil
}

func (c *minipoolBeginReduceBondDetailsContext) getMinipoolDetails(mp minipool.IMinipool, currentTime time.Time) api.MinipoolBeginReduceBondDetails {
	mpCommon := mp.Common()
	mpDetails := api.MinipoolBeginReduceBondDetails{
		Address: mpCommon.Address,
	}
	mpDetails.NodeDepositBalance = mpCommon.NodeDepositBalance.Get()
	mpDetails.NodeFee = mpCommon.NodeFee.Raw()

	mpv3, success := minipool.GetMinipoolAsV3(mp)
	if !success {
		mpDetails.MinipoolVersionTooLow = true
		return mpDetails
	}
	if mpCommon.Status.Formatted() != types.MinipoolStatus_Staking || mpCommon.IsFinalised.Get() {
		mpDetails.InvalidElState = true
		return mpDetails
	}
	if mpv3.IsBondReduceCancelled.Get() {
		mpDetails.AlreadyCancelled = true
		return mpDetails
	}

	reductionStart := mpv3.ReduceBondTime.Formatted()
	timeSinceBondReductionStart := currentTime.Sub(reductionStart)
	windowStart := c.oSettings.Minipool.BondReductionWindowStart.Formatted()
	windowEnd := windowStart + c.oSettings.Minipool.BondReductionWindowLength.Formatted()

	if timeSinceBondReductionStart < windowEnd {
		mpDetails.AlreadyInWindow = true
		return mpDetails
	}

	mpDetails.MatchRequest = big.NewInt(0).Sub(mpCommon.NodeDepositBalance.Get(), c.newBondAmountWei)
	if mpDetails.MatchRequest.Cmp(common.Big0) == 0 {
		mpDetails.NodeDepositTooLow = true
	}

	return mpDetails
}