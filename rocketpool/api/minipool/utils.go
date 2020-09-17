package minipool

import (
    "bytes"
    "context"
    "fmt"
    "math/big"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/rocket-pool/rocketpool-go/minipool"
    "github.com/rocket-pool/rocketpool-go/rocketpool"
    "github.com/rocket-pool/rocketpool-go/settings"
    "github.com/rocket-pool/rocketpool-go/tokens"
    "github.com/rocket-pool/rocketpool-go/types"
    "github.com/rocket-pool/rocketpool-go/utils/eth"
    "golang.org/x/sync/errgroup"

    "github.com/rocket-pool/smartnode/shared/services/beacon"
    "github.com/rocket-pool/smartnode/shared/types/api"
    "github.com/rocket-pool/smartnode/shared/utils/eth2"
)


// Validate that a minipool belongs to a node
func validateMinipoolOwner(mp *minipool.Minipool, nodeAddress common.Address) error {
    owner, err := mp.GetNodeAddress(nil)
    if err != nil {
        return err
    }
    if !bytes.Equal(owner.Bytes(), nodeAddress.Bytes()) {
        return fmt.Errorf("Minipool %s does not belong to the node", mp.Address.Hex())
    }
    return nil
}


// Get all node minipool details
func getNodeMinipoolDetails(rp *rocketpool.RocketPool, bc beacon.Client, nodeAddress common.Address) ([]api.MinipoolDetails, error) {

    // Data
    var wg1 errgroup.Group
    var addresses []common.Address
    var eth2Config beacon.Eth2Config
    var currentEpoch uint64
    var currentBlock uint64
    var withdrawalDelay uint64

    // Get minipool addresses
    wg1.Go(func() error {
        var err error
        addresses, err = minipool.GetNodeMinipoolAddresses(rp, nodeAddress, nil)
        return err
    })

    // Get eth2 config
    wg1.Go(func() error {
        var err error
        eth2Config, err = bc.GetEth2Config()
        return err
    })

    // Get current epoch
    wg1.Go(func() error {
        head, err := bc.GetBeaconHead()
        if err == nil {
            currentEpoch = head.Epoch
        }
        return err
    })

    // Get current block
    wg1.Go(func() error {
        header, err := rp.Client.HeaderByNumber(context.Background(), nil)
        if err == nil {
            currentBlock = header.Number.Uint64()
        }
        return err
    })

    // Get withdrawal delay
    wg1.Go(func() error {
        var err error
        withdrawalDelay, err = settings.GetMinipoolWithdrawalDelay(rp, nil)
        return err
    })

    // Wait for data
    if err := wg1.Wait(); err != nil {
        return []api.MinipoolDetails{}, err
    }

    // Data
    var wg2 errgroup.Group
    details := make([]api.MinipoolDetails, len(addresses))

    // Load details
    for mi, address := range addresses {
        mi, address := mi, address
        wg2.Go(func() error {
            mpDetails, err := getMinipoolDetails(rp, bc, address, eth2Config, currentEpoch, currentBlock, withdrawalDelay)
            if err == nil { details[mi] = mpDetails }
            return err
        })
    }

    // Wait for data
    if err := wg2.Wait(); err != nil {
        return []api.MinipoolDetails{}, err
    }

    // Return
    return details, nil

}


// Get a minipool's details
func getMinipoolDetails(rp *rocketpool.RocketPool, bc beacon.Client, minipoolAddress common.Address, eth2Config beacon.Eth2Config, currentEpoch, currentBlock, withdrawalDelay uint64) (api.MinipoolDetails, error) {

    // Create minipool
    mp, err := minipool.NewMinipool(rp, minipoolAddress)
    if err != nil {
        return api.MinipoolDetails{}, err
    }

    // Data
    var wg errgroup.Group
    details := api.MinipoolDetails{Address: minipoolAddress}

    // Load data
    wg.Go(func() error {
        var err error
        details.ValidatorPubkey, err = minipool.GetMinipoolPubkey(rp, minipoolAddress, nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.Status, err = mp.GetStatusDetails(nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.DepositType, err = mp.GetDepositType(nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.Node, err = mp.GetNodeDetails(nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.User, err = mp.GetUserDetails(nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.Staking, err = mp.GetStakingDetails(nil)
        return err
    })
    wg.Go(func() error {
        var err error
        details.Balances, err = tokens.GetBalances(rp, minipoolAddress, nil)
        return err
    })

    // Wait for data
    if err := wg.Wait(); err != nil {
        return api.MinipoolDetails{}, err
    }

    // Get validator details if staking
    if details.Status.Status == types.Staking {
        validator, err := getMinipoolValidatorDetails(rp, bc, details, eth2Config, currentEpoch)
        if err != nil {
            return api.MinipoolDetails{}, err
        }
        details.Validator = validator
    }

    // Update & return
    details.RefundAvailable = (details.Node.RefundBalance.Cmp(big.NewInt(0)) > 0)
    details.WithdrawalAvailable = (details.Status.Status == types.Withdrawable && (currentBlock - details.Status.StatusBlock) >= withdrawalDelay)
    details.CloseAvailable = (details.Status.Status == types.Dissolved)
    return details, nil

}


// Get a minipool's validator details
func getMinipoolValidatorDetails(rp *rocketpool.RocketPool, bc beacon.Client, minipoolDetails api.MinipoolDetails, eth2Config beacon.Eth2Config, currentEpoch uint64) (api.ValidatorDetails, error) {

    // Validator details
    details := api.ValidatorDetails{}

    // Get validator status
    validator, err := bc.GetValidatorStatus(minipoolDetails.ValidatorPubkey, nil)
    if err != nil {
        return api.ValidatorDetails{}, err
    }

    // Set validator details
    if validator.Exists {
        details.Exists = true
        if validator.ActivationEpoch <= currentEpoch {
            details.Active = true
        } else {
            details.ActivationDelay = time.Duration((validator.ActivationEpoch - currentEpoch) * eth2Config.SecondsPerEpoch) * time.Second
        }
    }

    // use deposit balances if validator not active
    if !details.Active {
        details.Balance.Add(minipoolDetails.Node.DepositBalance, minipoolDetails.User.DepositBalance)
        details.NodeBalance.Set(minipoolDetails.Node.DepositBalance)
        return details, nil
    }

    // Set validator balance
    details.Balance = eth.GweiToWei(float64(validator.Balance))

    // Get start epoch for expected node balance calculation
    startEpoch := eth2.EpochAt(eth2Config, uint64(minipoolDetails.User.DepositAssignedTime.Unix()))
    if startEpoch < validator.ActivationEpoch {
        startEpoch = validator.ActivationEpoch
    } else if startEpoch > currentEpoch {
        startEpoch = currentEpoch
    }

    // Get validator balance at start epoch
    validatorStart, err := bc.GetValidatorStatus(minipoolDetails.ValidatorPubkey, &beacon.ValidatorStatusOptions{Epoch: startEpoch})
    if err != nil {
        return api.ValidatorDetails{}, err
    }
    if !validatorStart.Exists {
        return api.ValidatorDetails{}, fmt.Errorf("Could not get validator %s balance at epoch %d", minipoolDetails.ValidatorPubkey.Hex(), startEpoch)
    }
    startBalance := eth.GweiToWei(float64(validatorStart.Balance))

    // Get expected node balance
    nodeBalance, err := minipool.GetMinipoolNodeRewardAmount(rp, minipoolDetails.Node.Fee, minipoolDetails.User.DepositBalance, startBalance, details.Balance, nil)
    if err != nil {
        return api.ValidatorDetails{}, err
    }
    details.NodeBalance = nodeBalance

    // Return
    return details, nil

}

