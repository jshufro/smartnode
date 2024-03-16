package node

import (
	"errors"
	"fmt"
	"math/big"
	"net/url"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	batch "github.com/rocket-pool/batch-query"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/rocket-pool/rocketpool-go/tokens"

	"github.com/rocket-pool/node-manager-core/api/server"
	"github.com/rocket-pool/node-manager-core/utils/input"
	"github.com/rocket-pool/smartnode/shared/types/api"
)

// ===============
// === Factory ===
// ===============

type nodeSwapRplContextFactory struct {
	handler *NodeHandler
}

func (f *nodeSwapRplContextFactory) Create(args url.Values) (*nodeSwapRplContext, error) {
	c := &nodeSwapRplContext{
		handler: f.handler,
	}
	inputErrs := []error{
		server.ValidateArg("amount", args, input.ValidateBigInt, &c.amount),
	}
	return c, errors.Join(inputErrs...)
}

func (f *nodeSwapRplContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterSingleStageRoute[*nodeSwapRplContext, api.NodeSwapRplData](
		router, "swap-rpl", f, f.handler.serviceProvider.ServiceProvider,
	)
}

// ===============
// === Context ===
// ===============

type nodeSwapRplContext struct {
	handler     *NodeHandler
	rp          *rocketpool.RocketPool
	nodeAddress common.Address

	amount     *big.Int
	fsrpl      *tokens.TokenRplFixedSupply
	rpl        *tokens.TokenRpl
	rplAddress common.Address
	balance    *big.Int
	allowance  *big.Int
}

func (c *nodeSwapRplContext) Initialize() error {
	sp := c.handler.serviceProvider
	c.rp = sp.GetRocketPool()
	c.nodeAddress, _ = sp.GetWallet().GetAddress()

	// Requirements
	err := sp.RequireNodeRegistered(c.handler.context)
	if err != nil {
		return err
	}

	// Bindings
	c.fsrpl, err = tokens.NewTokenRplFixedSupply(c.rp)
	if err != nil {
		return fmt.Errorf("error creating legacy RPL binding: %w", err)
	}
	c.rpl, err = tokens.NewTokenRpl(c.rp)
	if err != nil {
		return fmt.Errorf("error creating RPL binding: %w", err)
	}
	rplContract, err := c.rp.GetContract(rocketpool.ContractName_RocketTokenRPL)
	if err != nil {
		return fmt.Errorf("error creating RPL contract: %w", err)
	}
	c.rplAddress = rplContract.Address
	return nil
}

func (c *nodeSwapRplContext) GetState(mc *batch.MultiCaller) {
	c.fsrpl.BalanceOf(mc, &c.balance, c.nodeAddress)
	c.fsrpl.GetAllowance(mc, &c.allowance, c.nodeAddress, c.rplAddress)
}

func (c *nodeSwapRplContext) PrepareData(data *api.NodeSwapRplData, opts *bind.TransactOpts) error {
	data.InsufficientBalance = (c.amount.Cmp(c.balance) > 0)
	data.Allowance = c.allowance
	data.CanSwap = !(data.InsufficientBalance)

	if data.CanSwap {
		// Check allowance
		if c.amount.Cmp(c.allowance) > 0 {
			// Calculate max uint256 value
			approvalAmount := big.NewInt(2)
			approvalAmount = approvalAmount.Exp(approvalAmount, big.NewInt(256), nil)
			approvalAmount = approvalAmount.Sub(approvalAmount, big.NewInt(1))
			txInfo, err := c.fsrpl.Approve(c.rplAddress, approvalAmount, opts)
			if err != nil {
				return fmt.Errorf("error getting TX info to approve increasing legacy RPL's allowance: %w", err)
			}
			data.ApproveTxInfo = txInfo
		}

		txInfo, err := c.rpl.SwapFixedSupplyRplForRpl(c.amount, opts)
		if err != nil {
			return fmt.Errorf("error getting TX info for SwapFixedSupplyRPLForRPL: %w", err)
		}
		data.SwapTxInfo = txInfo
	}
	return nil
}