package node

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	ens "github.com/wealdtech/go-ens/v3"

	"github.com/rocket-pool/smartnode/rocketpool/common/server"
	"github.com/rocket-pool/smartnode/shared/types/api"
	"github.com/rocket-pool/smartnode/shared/utils/input"
)

// ===============
// === Factory ===
// ===============

type nodeResolveEnsContextFactory struct {
	handler *NodeHandler
}

func (f *nodeResolveEnsContextFactory) Create(args url.Values) (*nodeResolveEnsContext, error) {
	c := &nodeResolveEnsContext{
		handler: f.handler,
	}
	inputErrs := []error{
		server.ValidateArg("address", args, input.ValidateAddress, &c.address),
		server.GetStringFromVars("name", args, &c.name),
	}
	return c, errors.Join(inputErrs...)
}

func (f *nodeResolveEnsContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterQuerylessGet[*nodeResolveEnsContext, api.NodeResolveEnsData](
		router, "resolve-ens", f, f.handler.serviceProvider,
	)
}

// ===============
// === Context ===
// ===============

type nodeResolveEnsContext struct {
	handler *NodeHandler
	address common.Address
	name    string
}

func (c *nodeResolveEnsContext) PrepareData(data *api.NodeResolveEnsData, opts *bind.TransactOpts) error {
	sp := c.handler.serviceProvider
	rp := sp.GetRocketPool()

	emptyAddress := common.Address{}
	if c.address != emptyAddress {
		data.Address = c.address
		name, err := ens.ReverseResolve(rp.Client, c.address)
		if err != nil {
			data.FormattedName = data.Address.Hex()
		} else {
			data.EnsName = name
			data.FormattedName = fmt.Sprintf("%s (%s)", name, data.Address.Hex())
		}
	} else if c.name != "" {
		data.EnsName = c.name
		address, err := ens.Resolve(rp.Client, c.name)
		if err != nil {
			return fmt.Errorf("error resolving ENS address for [%s]: %w", c.name, err)
		}
		data.Address = address
		data.FormattedName = fmt.Sprintf("%s (%s)", c.name, data.Address.Hex())
	} else {
		return fmt.Errorf("either address or name must not be empty")
	}

	return nil
}
