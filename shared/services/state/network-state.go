package state

import (
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/rocket-pool/rocketpool-go/types"
	"github.com/rocket-pool/rocketpool-go/utils/eth"
	rpstate "github.com/rocket-pool/rocketpool-go/utils/state"
	"github.com/rocket-pool/smartnode/shared/services/beacon"
	"github.com/rocket-pool/smartnode/shared/services/config"
	"github.com/rocket-pool/smartnode/shared/utils/log"
	"golang.org/x/sync/errgroup"
)

const (
	threadLimit int = 6
)

type NetworkState struct {
	// Block / slot for this state
	ElBlockNumber    uint64
	BeaconSlotNumber uint64
	BeaconConfig     beacon.Eth2Config

	// Network details
	NetworkDetails *rpstate.NetworkDetails

	// Node details
	NodeDetails          []rpstate.NativeNodeDetails
	NodeDetailsByAddress map[common.Address]*rpstate.NativeNodeDetails

	// Minipool details
	MinipoolDetails          []rpstate.NativeMinipoolDetails
	MinipoolDetailsByAddress map[common.Address]*rpstate.NativeMinipoolDetails
	MinipoolDetailsByNode    map[common.Address][]*rpstate.NativeMinipoolDetails

	// Validator details
	ValidatorDetails map[types.ValidatorPubkey]beacon.ValidatorStatus

	// Oracle DAO details
	OracleDaoMemberDetails []rpstate.OracleDaoMemberDetails

	// Internal fields
	log *log.ColorLogger
}

// Creates a snapshot of the entire Rocket Pool network state, on both the Execution and Consensus layers
func CreateNetworkState(cfg *config.RocketPoolConfig, rp *rocketpool.RocketPool, ec rocketpool.ExecutionClient, bc beacon.Client, log *log.ColorLogger, slotNumber uint64, beaconConfig beacon.Eth2Config) (*NetworkState, error) {
	// Get the relevant network contracts
	multicallerAddress := common.HexToAddress(cfg.Smartnode.GetMulticallAddress())
	balanceBatcherAddress := common.HexToAddress(cfg.Smartnode.GetBalanceBatcherAddress())

	// Get the execution block for the given slot
	beaconBlock, exists, err := bc.GetBeaconBlock(fmt.Sprintf("%d", slotNumber))
	if err != nil {
		return nil, fmt.Errorf("error getting Beacon block for slot %d: %w", slotNumber, err)
	}
	if !exists {
		return nil, fmt.Errorf("slot %d did not have a Beacon block", slotNumber)
	}

	// Get the corresponding block on the EL
	elBlockNumber := beaconBlock.ExecutionBlockNumber
	opts := &bind.CallOpts{
		BlockNumber: big.NewInt(0).SetUint64(elBlockNumber),
	}

	// Create the state wrapper
	state := &NetworkState{
		NodeDetailsByAddress:     map[common.Address]*rpstate.NativeNodeDetails{},
		MinipoolDetailsByAddress: map[common.Address]*rpstate.NativeMinipoolDetails{},
		MinipoolDetailsByNode:    map[common.Address][]*rpstate.NativeMinipoolDetails{},
		BeaconSlotNumber:         slotNumber,
		ElBlockNumber:            elBlockNumber,
		BeaconConfig:             beaconConfig,
		log:                      log,
	}

	state.logLine("Getting network state for EL block %d, Beacon slot %d", elBlockNumber, slotNumber)
	start := time.Now()

	// Network contracts and details
	contracts, err := rpstate.NewNetworkContracts(rp, multicallerAddress, balanceBatcherAddress, opts)
	if err != nil {
		return nil, fmt.Errorf("error getting network contracts: %w", err)
	}
	state.NetworkDetails, err = rpstate.NewNetworkDetails(rp, contracts)
	if err != nil {
		return nil, fmt.Errorf("error getting network details: %w", err)
	}
	state.logLine("1/6 - Retrieved network details (%s so far)", time.Since(start))

	// Node details
	state.NodeDetails, err = rpstate.GetAllNativeNodeDetails(rp, contracts)
	if err != nil {
		return nil, fmt.Errorf("error getting all node details: %w", err)
	}
	state.logLine("2/6 - Retrieved node details (%s so far)", time.Since(start))

	// Minipool details
	state.MinipoolDetails, err = rpstate.GetAllNativeMinipoolDetails(rp, contracts)
	if err != nil {
		return nil, fmt.Errorf("error getting all minipool details: %w", err)
	}
	state.logLine("3/6 - Retrieved minipool details (%s so far)", time.Since(start))

	// Create the node lookup
	for i, details := range state.NodeDetails {
		state.NodeDetailsByAddress[details.NodeAddress] = &state.NodeDetails[i]
	}

	// Create the minipool lookups
	pubkeys := make([]types.ValidatorPubkey, 0, len(state.MinipoolDetails))
	emptyPubkey := types.ValidatorPubkey{}
	for i, details := range state.MinipoolDetails {
		state.MinipoolDetailsByAddress[details.MinipoolAddress] = &state.MinipoolDetails[i]
		if details.Pubkey != emptyPubkey {
			pubkeys = append(pubkeys, details.Pubkey)
		}

		// The map of nodes to minipools
		nodeList, exists := state.MinipoolDetailsByNode[details.NodeAddress]
		if !exists {
			nodeList = []*rpstate.NativeMinipoolDetails{}
		}
		nodeList = append(nodeList, &state.MinipoolDetails[i])
		state.MinipoolDetailsByNode[details.NodeAddress] = nodeList
	}

	// Calculate avg node fees and distributor shares
	for _, details := range state.NodeDetails {
		rpstate.CalculateAverageFeeAndDistributorShares(rp, contracts, details, state.MinipoolDetailsByNode[details.NodeAddress])
	}

	// Oracle DAO member details
	state.OracleDaoMemberDetails, err = rpstate.GetAllOracleDaoMemberDetails(rp, contracts)
	if err != nil {
		return nil, fmt.Errorf("error getting Oracle DAO details: %w", err)
	}
	state.logLine("4/6 - Retrieved Oracle DAO details (%s so far)", time.Since(start))

	// Get the validator stats from Beacon
	statusMap, err := bc.GetValidatorStatuses(pubkeys, &beacon.ValidatorStatusOptions{
		Slot: &slotNumber,
	})
	if err != nil {
		return nil, err
	}
	state.ValidatorDetails = statusMap
	state.logLine("5/6 - Retrieved validator details (total time: %s)", time.Since(start))

	// Get the complete node and user shares
	mpds := make([]*rpstate.NativeMinipoolDetails, len(state.MinipoolDetails))
	beaconBalances := make([]*big.Int, len(state.MinipoolDetails))
	for i, mpd := range state.MinipoolDetails {
		mpds[i] = &state.MinipoolDetails[i]
		validator := state.ValidatorDetails[mpd.Pubkey]
		if !validator.Exists {
			beaconBalances[i] = big.NewInt(0)
		} else {
			beaconBalances[i] = eth.GweiToWei(float64(validator.Balance))
		}
	}
	err = rpstate.CalculateCompleteMinipoolShares(rp, contracts, mpds, beaconBalances)
	if err != nil {
		return nil, err
	}
	state.ValidatorDetails = statusMap
	state.logLine("6/6 - Calculated complete node and user balance shares (total time: %s)", time.Since(start))

	return state, nil
}

// Creates a snapshot of the Rocket Pool network, but only for a single node
// Also gets the total effective RPL stake of the network for convenience since this is required by several node routines
func CreateNetworkStateForNode(cfg *config.RocketPoolConfig, rp *rocketpool.RocketPool, ec rocketpool.ExecutionClient, bc beacon.Client, log *log.ColorLogger, slotNumber uint64, beaconConfig beacon.Eth2Config, nodeAddress common.Address, calculateTotalEffectiveStake bool) (*NetworkState, *big.Int, error) {
	steps := 5
	if calculateTotalEffectiveStake {
		steps++
	}

	// Get the relevant network contracts
	multicallerAddress := common.HexToAddress(cfg.Smartnode.GetMulticallAddress())
	balanceBatcherAddress := common.HexToAddress(cfg.Smartnode.GetBalanceBatcherAddress())

	// Get the execution block for the given slot
	beaconBlock, exists, err := bc.GetBeaconBlock(fmt.Sprintf("%d", slotNumber))
	if err != nil {
		return nil, nil, fmt.Errorf("error getting Beacon block for slot %d: %w", slotNumber, err)
	}
	if !exists {
		return nil, nil, fmt.Errorf("slot %d did not have a Beacon block", slotNumber)
	}

	// Get the corresponding block on the EL
	elBlockNumber := beaconBlock.ExecutionBlockNumber
	opts := &bind.CallOpts{
		BlockNumber: big.NewInt(0).SetUint64(elBlockNumber),
	}

	// Create the state wrapper
	state := &NetworkState{
		NodeDetailsByAddress:     map[common.Address]*rpstate.NativeNodeDetails{},
		MinipoolDetailsByAddress: map[common.Address]*rpstate.NativeMinipoolDetails{},
		MinipoolDetailsByNode:    map[common.Address][]*rpstate.NativeMinipoolDetails{},
		BeaconSlotNumber:         slotNumber,
		ElBlockNumber:            elBlockNumber,
		BeaconConfig:             beaconConfig,
		log:                      log,
	}

	state.logLine("Getting network state for EL block %d, Beacon slot %d", elBlockNumber, slotNumber)
	start := time.Now()

	// Network contracts and details
	contracts, err := rpstate.NewNetworkContracts(rp, multicallerAddress, balanceBatcherAddress, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting network contracts: %w", err)
	}
	state.NetworkDetails, err = rpstate.NewNetworkDetails(rp, contracts)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting network details: %w", err)
	}
	state.logLine("1/%d - Retrieved network details (%s so far)", steps, time.Since(start))

	// Node details
	nodeDetails, err := rpstate.GetNativeNodeDetails(rp, contracts, nodeAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting node details: %w", err)
	}
	state.NodeDetails = []rpstate.NativeNodeDetails{nodeDetails}
	state.logLine("2/%d - Retrieved node details (%s so far)", steps, time.Since(start))

	// Minipool details
	state.MinipoolDetails, err = rpstate.GetNodeNativeMinipoolDetails(rp, contracts, nodeAddress)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting all minipool details: %w", err)
	}
	state.logLine("3/%d - Retrieved minipool details (%s so far)", steps, time.Since(start))

	// Create the node lookup
	for i, details := range state.NodeDetails {
		state.NodeDetailsByAddress[details.NodeAddress] = &state.NodeDetails[i]
	}

	// Create the minipool lookups
	pubkeys := make([]types.ValidatorPubkey, 0, len(state.MinipoolDetails))
	emptyPubkey := types.ValidatorPubkey{}
	for i, details := range state.MinipoolDetails {
		state.MinipoolDetailsByAddress[details.MinipoolAddress] = &state.MinipoolDetails[i]
		if details.Pubkey != emptyPubkey {
			pubkeys = append(pubkeys, details.Pubkey)
		}

		// The map of nodes to minipools
		nodeList, exists := state.MinipoolDetailsByNode[details.NodeAddress]
		if !exists {
			nodeList = []*rpstate.NativeMinipoolDetails{}
		}
		nodeList = append(nodeList, &state.MinipoolDetails[i])
		state.MinipoolDetailsByNode[details.NodeAddress] = nodeList
	}

	// Calculate avg node fees and distributor shares
	for _, details := range state.NodeDetails {
		rpstate.CalculateAverageFeeAndDistributorShares(rp, contracts, details, state.MinipoolDetailsByNode[details.NodeAddress])
	}

	// Get the total network effective RPL stake
	currentStep := 4
	var totalEffectiveStake *big.Int
	if calculateTotalEffectiveStake {
		totalEffectiveStake, err = rpstate.GetTotalEffectiveRplStake(rp, contracts)
		if err != nil {
			return nil, nil, fmt.Errorf("error calculating total effective RPL stake for the network: %w", err)
		}
		state.logLine("%d/%d - Calculated total effective stake (total time: %s)", currentStep, steps, time.Since(start))
		currentStep++
	}

	// Get the validator stats from Beacon
	statusMap, err := bc.GetValidatorStatuses(pubkeys, &beacon.ValidatorStatusOptions{
		Slot: &slotNumber,
	})
	if err != nil {
		return nil, nil, err
	}
	state.ValidatorDetails = statusMap
	state.logLine("%d/%d - Retrieved validator details (total time: %s)", currentStep, steps, time.Since(start))
	currentStep++

	// Get the complete node and user shares
	mpds := make([]*rpstate.NativeMinipoolDetails, len(state.MinipoolDetails))
	beaconBalances := make([]*big.Int, len(state.MinipoolDetails))
	for i, mpd := range state.MinipoolDetails {
		mpds[i] = &state.MinipoolDetails[i]
		validator := state.ValidatorDetails[mpd.Pubkey]
		if !validator.Exists {
			beaconBalances[i] = big.NewInt(0)
		} else {
			beaconBalances[i] = eth.GweiToWei(float64(validator.Balance))
		}
	}
	err = rpstate.CalculateCompleteMinipoolShares(rp, contracts, mpds, beaconBalances)
	if err != nil {
		return nil, nil, err
	}
	state.ValidatorDetails = statusMap
	state.logLine("%d/%d - Calculated complete node and user balance shares (total time: %s)", currentStep, steps, time.Since(start))

	return state, totalEffectiveStake, nil
}

// Calculate the true effective stakes of all nodes in the state, using the validator status
// on Beacon as a reference for minipool eligibility instead of the EL-based minipool status
func (s *NetworkState) CalculateTrueEffectiveStakes(scaleByParticipation bool, allowRplForUnstartedValidators bool) (map[common.Address]*big.Int, *big.Int, error) {
	effectiveStakes := make(map[common.Address]*big.Int, len(s.NodeDetails))
	totalEffectiveStake := big.NewInt(0)
	intervalDurationBig := big.NewInt(int64(s.NetworkDetails.IntervalDuration.Seconds()))
	genesisTime := time.Unix(int64(s.BeaconConfig.GenesisTime), 0)
	slotOffset := time.Duration(s.BeaconSlotNumber*s.BeaconConfig.SecondsPerSlot) * time.Second
	slotTime := genesisTime.Add(slotOffset)

	nodeCount := uint64(len(s.NodeDetails))
	effectiveStakeSlice := make([]*big.Int, nodeCount)

	// Get the effective stake for each node
	var wg errgroup.Group
	wg.SetLimit(threadLimit)
	for i, node := range s.NodeDetails {
		i := i
		node := node
		wg.Go(func() error {
			eligibleBorrowedEth := big.NewInt(0)
			eb16s := 0
			eb8s := 0
			for _, mpd := range s.MinipoolDetailsByNode[node.NodeAddress] {
				// It must exist and be staking
				if mpd.Exists && mpd.Status == types.Staking {
					// Doesn't exist on Beacon yet
					validatorStatus, exists := s.ValidatorDetails[mpd.Pubkey]
					if !exists {
						//s.logLine("NOTE: minipool %s (pubkey %s) didn't exist, ignoring it in effective RPL calculation", mpd.MinipoolAddress.Hex(), mpd.Pubkey.Hex())
						continue
					}

					intervalEndEpoch := s.BeaconSlotNumber / s.BeaconConfig.SlotsPerEpoch
					if !allowRplForUnstartedValidators {
						// Starts too late
						if validatorStatus.ActivationEpoch > intervalEndEpoch {
							//s.logLine("NOTE: Minipool %s starts on epoch %d which is after interval epoch %d so it's not eligible for RPL rewards", mpd.MinipoolAddress.Hex(), validatorStatus.ActivationEpoch, intervalEndEpoch)
							continue
						}

					}
					// Already exited
					if validatorStatus.ExitEpoch <= intervalEndEpoch {
						//s.logLine("NOTE: Minipool %s exited on epoch %d which is not after interval epoch %d so it's not eligible for RPL rewards", mpd.MinipoolAddress.Hex(), validatorStatus.ExitEpoch, intervalEndEpoch)
						continue
					}
					// It's eligible, so add up the borrowed and bonded amounts
					eligibleBorrowedEth.Add(eligibleBorrowedEth, mpd.UserDepositBalance)

					if mpd.NodeDepositBalance.Cmp(eth.EthToWei(8)) == 0 {
						eb8s++
					} else if mpd.NodeDepositBalance.Cmp(eth.EthToWei(16)) == 0 {
						eb16s++
					}

				}
			}

			// minCollateral := borrowedEth * minCollateralFraction / ratio
			// NOTE: minCollateralFraction and ratio are both percentages, but multiplying and dividing by them cancels out the need for normalization by eth.EthToWei(1)
			minCollateral := big.NewInt(0).Mul(eligibleBorrowedEth, s.NetworkDetails.MinCollateralFraction)
			minCollateral.Div(minCollateral, s.NetworkDetails.RplPrice)

			// Calculate the effective stake
			nodeStake := big.NewInt(0).Set(node.RplStake)
			if nodeStake.Cmp(minCollateral) == -1 || eligibleBorrowedEth.Cmp(big.NewInt(0)) == 0 {
				// Under min collateral
				nodeStake.SetUint64(0)
			} else {
				// Calculate a few terms.
				stakedRplValueInEth := big.NewInt(0).Mul(nodeStake, s.NetworkDetails.RplPrice)
				stakedRplValueInEth.Div(stakedRplValueInEth, big.NewInt(1e18))

				// Adjust eligibleBorrowedEth to find the hypothetical borrowed eth
				// assuming that all eb16 minipools will be migrated to leb8s should there be enough
				// collateral available to do so.

				// How much additional eth can be borrowed by bond reduction?
				// Each eb16 can be converted into 2 leb8s. That converts 16 borrowed into 48 borrowed, net
				// difference of 32.
				maxReductionBorrow := big.NewInt(0).Mul(big.NewInt(int64(eb16s)), eth.EthToWei(32))
				maxReductionBorrow.Add(maxReductionBorrow, eligibleBorrowedEth)

				// How much additional borrowing can we do based on our rpl stake?
				// The limit is rpl_stake_in_eth * 10
				maxBorrow := big.NewInt(0).Mul(stakedRplValueInEth, big.NewInt(10))
				// We can only borrow in 8 eth increments so divmul
				maxBorrow.Mul(maxBorrow.Div(maxBorrow, eth.EthToWei(8)), eth.EthToWei(8))
				// Take the lower of the two numbers and use it as our eligibleBorrowedEth
				if maxBorrow.Cmp(maxReductionBorrow) > 0 {
					eligibleBorrowedEth.Set(maxReductionBorrow)
				} else {
					eligibleBorrowedEth.Set(maxBorrow)
				}

				// If between (inclusive 0.1 and 0.15, weight is just 100 * staked_rpl_value_in_eth
				// we already know we're above 10% of borrowed.
				midCollateral := big.NewInt(0).Mul(eligibleBorrowedEth, big.NewInt(150000000000000000))
				midCollateral.Div(midCollateral, s.NetworkDetails.RplPrice)

				var weight *big.Float
				if nodeStake.Cmp(midCollateral) <= 0 {
					weight = big.NewFloat(0).Mul(big.NewFloat(100), big.NewFloat(0).SetInt(stakedRplValueInEth))
				} else {
					lnArgs, _ :=
						big.NewFloat(0).Sub(
							big.NewFloat(0).Mul(
								big.NewFloat(100.0),
								big.NewFloat(0).Quo(
									big.NewFloat(0.0).SetInt(stakedRplValueInEth),
									big.NewFloat(0.0).SetInt(eligibleBorrowedEth),
								),
							),
							big.NewFloat(13.0),
						).Float64()
					weight = big.NewFloat(0).Mul(
						big.NewFloat(0).Add(
							big.NewFloat(13.6137),
							big.NewFloat(0).Mul(
								big.NewFloat(2.0),
								big.NewFloat(math.Log(lnArgs)),
							),
						),
						big.NewFloat(0).SetInt(eligibleBorrowedEth),
					)
				}

				approx, _ := weight.Float64()
				if math.IsNaN(approx) {
					nodeStake.SetUint64(0)
				} else {
					integered, _ := weight.Int(nil)
					nodeStake.Set(integered)
				}
			}

			// Scale the effective stake by the participation in the current interval
			if scaleByParticipation {
				// Get the timestamp of the node's registration
				regTimeBig := node.RegistrationTime
				regTime := time.Unix(regTimeBig.Int64(), 0)

				// Get the actual effective stake, scaled based on participation
				eligibleDuration := slotTime.Sub(regTime)
				if eligibleDuration < s.NetworkDetails.IntervalDuration {
					eligibleSeconds := big.NewInt(int64(eligibleDuration / time.Second))
					nodeStake.Mul(nodeStake, eligibleSeconds)
					nodeStake.Div(nodeStake, intervalDurationBig)
				}
			}

			effectiveStakeSlice[i] = nodeStake
			return nil
		})
	}

	if err := wg.Wait(); err != nil {
		return nil, nil, err
	}

	// Tally everything up and make the node stake map
	for i, nodeStake := range effectiveStakeSlice {
		node := s.NodeDetails[i]
		effectiveStakes[node.NodeAddress] = nodeStake
		totalEffectiveStake.Add(totalEffectiveStake, nodeStake)
	}

	return effectiveStakes, totalEffectiveStake, nil

}

// Logs a line if the logger is specified
func (s *NetworkState) logLine(format string, v ...interface{}) {
	if s.log != nil {
		s.log.Printlnf(format, v...)
	}
}
