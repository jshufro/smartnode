package wallet

import (
	"errors"
	"fmt"
	"net/url"
	_ "time/tzdata"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"

	"github.com/rocket-pool/node-manager-core/api/server"
	"github.com/rocket-pool/node-manager-core/api/types"
	"github.com/rocket-pool/node-manager-core/utils/input"
)

// ===============
// === Factory ===
// ===============

type walletSendMessageContextFactory struct {
	handler *WalletHandler
}

func (f *walletSendMessageContextFactory) Create(args url.Values) (*walletSendMessageContext, error) {
	c := &walletSendMessageContext{
		handler: f.handler,
	}
	inputErrs := []error{
		server.ValidateArg("message", args, input.ValidateByteArray, &c.message),
		server.ValidateArg("address", args, input.ValidateAddress, &c.address),
	}
	return c, errors.Join(inputErrs...)
}

func (f *walletSendMessageContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterQuerylessGet[*walletSendMessageContext, types.TxInfoData](
		router, "send-message", f, f.handler.serviceProvider.ServiceProvider,
	)
}

// ===============
// === Context ===
// ===============

type walletSendMessageContext struct {
	handler *WalletHandler
	message []byte
	address common.Address
}

func (c *walletSendMessageContext) PrepareData(data *types.TxInfoData, opts *bind.TransactOpts) error {
	sp := c.handler.serviceProvider
	ec := sp.GetEthClient()

	err := errors.Join(
		sp.RequireWalletReady(),
	)
	if err != nil {
		return err
	}

	txInfo, err := eth.NewTransactionInfoRaw(ec, c.address, c.message, opts)
	if err != nil {
		return fmt.Errorf("error creating TX info: %w", err)
	}
	data.TxInfo = txInfo
	return nil
}
