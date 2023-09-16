package minipool

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"golang.org/x/sync/errgroup"

	batch "github.com/rocket-pool/batch-query"
	"github.com/rocket-pool/rocketpool-go/core"
	"github.com/rocket-pool/rocketpool-go/minipool"
	"github.com/rocket-pool/rocketpool-go/node"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/rocket-pool/rocketpool-go/settings"
	"github.com/rocket-pool/rocketpool-go/tokens"
	rptypes "github.com/rocket-pool/rocketpool-go/types"
	"github.com/rocket-pool/rocketpool-go/utils/eth"
	"github.com/rocket-pool/smartnode/shared/services/beacon"
	"github.com/rocket-pool/smartnode/shared/types/api"
)

type minipoolStatusManager struct {
	delegate      *core.Contract
	pSettings     *settings.ProtocolDaoSettings
	oSettings     *settings.OracleDaoSettings
	reth          *tokens.TokenReth
	rpl           *tokens.TokenRpl
	fsrpl         *tokens.TokenRplFixedSupply
	rethBalances  []*big.Int
	rplBalances   []*big.Int
	fsrplBalances []*big.Int
}

func (m *minipoolStatusManager) CreateBindings(rp *rocketpool.RocketPool) error {
	var err error
	m.delegate, err = rp.GetContract(rocketpool.ContractName_RocketMinipoolDelegate)
	if err != nil {
		return fmt.Errorf("error getting minipool delegate binding: %w", err)
	}
	m.pSettings, err = settings.NewProtocolDaoSettings(rp)
	if err != nil {
		return fmt.Errorf("error creating pDAO settings binding: %w", err)
	}
	m.oSettings, err = settings.NewOracleDaoSettings(rp)
	if err != nil {
		return fmt.Errorf("error creating oDAO settings binding: %w", err)
	}
	m.reth, err = tokens.NewTokenReth(rp)
	if err != nil {
		return fmt.Errorf("error creating rETH token binding: %w", err)
	}
	m.rpl, err = tokens.NewTokenRpl(rp)
	if err != nil {
		return fmt.Errorf("error creating RPL token binding: %w", err)
	}
	m.fsrpl, err = tokens.NewTokenRplFixedSupply(rp)
	if err != nil {
		return fmt.Errorf("error creating legacy RPL token binding: %w", err)
	}
	return nil
}

func (m *minipoolStatusManager) GetState(node *node.Node, mc *batch.MultiCaller) {
	m.pSettings.GetMinipoolLaunchTimeout(mc)
	m.oSettings.GetScrubPeriod(mc)
	m.oSettings.GetPromotionScrubPeriod(mc)
}

func (m *minipoolStatusManager) CheckState(node *node.Node, response *api.MinipoolStatusData) bool {
	// Provision the token balance counts
	minipoolCount := node.Details.MinipoolCount.Formatted()
	m.rethBalances = make([]*big.Int, minipoolCount)
	m.rplBalances = make([]*big.Int, minipoolCount)
	m.fsrplBalances = make([]*big.Int, minipoolCount)
	return true
}

func (m *minipoolStatusManager) GetMinipoolDetails(mc *batch.MultiCaller, mp minipool.Minipool, index int) {
	address := mp.GetMinipoolCommon().Details.Address
	mp.QueryAllDetails(mc)
	m.reth.GetBalance(mc, &m.rethBalances[index], address)
	m.rpl.GetBalance(mc, &m.rplBalances[index], address)
	m.fsrpl.GetBalance(mc, &m.fsrplBalances[index], address)
}

func (m *minipoolStatusManager) PrepareResponse(rp *rocketpool.RocketPool, bc beacon.Client, addresses []common.Address, mps []minipool.Minipool, response *api.MinipoolStatusData) error {
	// Data
	var wg1 errgroup.Group
	var eth2Config beacon.Eth2Config
	var currentHeader *types.Header
	var balances []*big.Int

	// Get the current ETH balances of each minipool
	wg1.Go(func() error {
		var err error
		balances, err = rp.BalanceBatcher.GetEthBalances(addresses, nil)
		if err != nil {
			return fmt.Errorf("error getting minipool balances: %w", err)
		}
		return nil
	})

	// Get eth2 config
	wg1.Go(func() error {
		var err error
		eth2Config, err = bc.GetEth2Config()
		if err != nil {
			return fmt.Errorf("error getting Beacon config: %w", err)
		}
		return nil
	})

	// Get current block header
	wg1.Go(func() error {
		var err error
		currentHeader, err = rp.Client.HeaderByNumber(context.Background(), nil)
		if err != nil {
			return fmt.Errorf("error getting latest block header: %w", err)
		}
		return nil
	})

	// Wait for data
	if err := wg1.Wait(); err != nil {
		return err
	}

	// Calculate the current epoch from the header and Beacon config
	genesis := time.Unix(int64(eth2Config.GenesisTime), 0)
	currentTime := time.Unix(int64(currentHeader.Time), 0)
	timeSinceGenesis := currentTime.Sub(genesis)
	currentEpoch := uint64(timeSinceGenesis.Seconds()) / eth2Config.SecondsPerEpoch

	// Get some protocol settings
	launchTimeout := m.pSettings.Details.Minipool.LaunchTimeout.Formatted()
	scrubPeriod := m.oSettings.Details.Minipools.ScrubPeriod.Formatted()
	promotionScrubPeriod := m.oSettings.Details.Minipools.PromotionScrubPeriod.Formatted()

	// Get the statuses on Beacon
	pubkeys := make([]rptypes.ValidatorPubkey, 0, len(addresses))
	for _, mp := range mps {
		mpCommon := mp.GetMinipoolCommon()
		status := mpCommon.Details.Status.Formatted()
		if status == rptypes.Staking || (status == rptypes.Dissolved && !mpCommon.Details.IsFinalised) {
			pubkeys = append(pubkeys, mpCommon.Details.Pubkey)
		}
	}
	beaconStatuses, err := bc.GetValidatorStatuses(pubkeys, nil)
	if err != nil {
		return fmt.Errorf("error getting validator statuses on Beacon: %w", err)
	}

	// Assign the details
	details := make([]api.MinipoolDetails, len(mps))
	for i, mp := range mps {
		mpCommonDetails := mp.GetMinipoolCommon().Details
		pubkey := mpCommonDetails.Pubkey
		mpv3, isv3 := minipool.GetMinipoolAsV3(mp)

		// Basic info
		mpDetails := api.MinipoolDetails{
			Address: mpCommonDetails.Address,
		}
		mpDetails.ValidatorPubkey = pubkey
		mpDetails.Status.Status = mpCommonDetails.Status.Formatted()
		mpDetails.Status.StatusBlock = mpCommonDetails.StatusBlock.Formatted()
		mpDetails.Status.StatusTime = mpCommonDetails.StatusTime.Formatted()
		mpDetails.DepositType = mpCommonDetails.DepositType.Formatted()
		mpDetails.Node.Address = mpCommonDetails.NodeAddress
		mpDetails.Node.DepositAssigned = mpCommonDetails.NodeDepositAssigned
		mpDetails.Node.DepositBalance = mpCommonDetails.NodeDepositBalance
		mpDetails.Node.Fee = mpCommonDetails.NodeFee.Formatted()
		mpDetails.Node.RefundBalance = mpCommonDetails.NodeRefundBalance
		mpDetails.User.DepositAssigned = mpCommonDetails.UserDepositAssigned
		mpDetails.User.DepositAssignedTime = mpCommonDetails.UserDepositAssignedTime.Formatted()
		mpDetails.User.DepositBalance = mpCommonDetails.UserDepositBalance
		mpDetails.Balances.Eth = balances[i]
		mpDetails.Balances.Reth = m.rethBalances[i]
		mpDetails.Balances.Rpl = m.rplBalances[i]
		mpDetails.Balances.FixedSupplyRpl = m.fsrplBalances[i]
		mpDetails.UseLatestDelegate = mpCommonDetails.IsUseLatestDelegateEnabled
		mpDetails.Delegate = mpCommonDetails.DelegateAddress
		mpDetails.PreviousDelegate = mpCommonDetails.PreviousDelegateAddress
		mpDetails.EffectiveDelegate = mpCommonDetails.EffectiveDelegateAddress
		mpDetails.Finalised = mpCommonDetails.IsFinalised
		mpDetails.Penalties = mpCommonDetails.PenaltyCount.Formatted()
		mpDetails.Queue.Position = mpCommonDetails.QueuePosition.Formatted() + 1 // Queue pos is -1 indexed so make it 0
		mpDetails.RefundAvailable = (mpDetails.Node.RefundBalance.Cmp(zero()) > 0) && (mpDetails.Balances.Eth.Cmp(mpDetails.Node.RefundBalance) >= 0)
		mpDetails.CloseAvailable = (mpDetails.Status.Status == rptypes.Dissolved)
		mpDetails.WithdrawalAvailable = (mpDetails.Status.Status == rptypes.Withdrawable)

		// Check the stake status of each minipool
		if mpDetails.Status.Status == rptypes.Prelaunch {
			creationTime := mpDetails.Status.StatusTime
			dissolveTime := creationTime.Add(launchTimeout)
			remainingTime := creationTime.Add(scrubPeriod).Sub(currentTime)
			if remainingTime < 0 {
				mpDetails.CanStake = true
				mpDetails.TimeUntilDissolve = time.Until(dissolveTime)
			}
		}

		// Atlas info
		if isv3 {
			mpDetails.Status.IsVacant = mpv3.Details.IsVacant
			mpDetails.ReduceBondTime = mpv3.Details.ReduceBondTime.Formatted()

			// Check the promotion status of each minipool
			if mpDetails.Status.IsVacant {
				creationTime := mpDetails.Status.StatusTime
				dissolveTime := creationTime.Add(launchTimeout)
				remainingTime := creationTime.Add(promotionScrubPeriod).Sub(currentTime)
				if remainingTime < 0 {
					mpDetails.CanPromote = true
					mpDetails.TimeUntilDissolve = time.Until(dissolveTime)
				}
			}
		}

		// Beacon info
		beaconStatus, existsOnBeacon := beaconStatuses[pubkey]
		validatorActivated := false
		mpDetails.Validator.Exists = existsOnBeacon
		if existsOnBeacon {
			mpDetails.Validator.Active = (beaconStatus.ActivationEpoch < currentEpoch && beaconStatus.ExitEpoch > currentEpoch)
			mpDetails.Validator.Index = beaconStatus.Index
			validatorActivated = (beaconStatus.ActivationEpoch < currentEpoch)
		}
		if !validatorActivated {
			// Use deposit balances if the validator isn't activated yet
			mpDetails.Validator.Balance = big.NewInt(0).Add(mpDetails.Node.DepositBalance, mpDetails.User.DepositBalance)
			mpDetails.Validator.NodeBalance = big.NewInt(0).Set(mpDetails.Node.DepositBalance)
		} else {
			mpDetails.Validator.Balance = eth.GweiToWei(float64(beaconStatus.Balance))
		}

		details[i] = mpDetails
	}

	// Calculate the node share of each minipool balance
	err = rp.BatchQuery(len(addresses), minipoolBatchSize, func(mc *batch.MultiCaller, i int) error {
		mpCommon := mps[i].GetMinipoolCommon()
		mpDetails := &details[i]

		// Get the node share of the ETH balance
		if mpDetails.Balances.Eth.Cmp(mpDetails.Node.RefundBalance) == -1 {
			mpDetails.NodeShareOfEthBalance = big.NewInt(0)
		} else {
			effectiveBalance := big.NewInt(0).Sub(mpDetails.Balances.Eth, mpDetails.Node.RefundBalance)
			mpCommon.CalculateNodeShare(mc, &mpDetails.NodeShareOfEthBalance, effectiveBalance)
		}

		// Get the node share of the Beacon balance
		pubkey := mpCommon.Details.Pubkey
		beaconStatus, existsOnBeacon := beaconStatuses[pubkey]
		validatorActivated := (beaconStatus.ActivationEpoch < currentEpoch)
		if validatorActivated && existsOnBeacon {
			mpCommon.CalculateNodeShare(mc, &mpDetails.Validator.NodeBalance, mpDetails.Validator.Balance)
		}

		return nil
	}, nil)

	response.LatestDelegate = *m.delegate.Address
	return nil
}
