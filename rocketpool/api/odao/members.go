package odao

import (
	"fmt"
	"net/url"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	batch "github.com/rocket-pool/batch-query"
	"github.com/rocket-pool/rocketpool-go/dao/oracle"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/rocket-pool/smartnode/rocketpool/common/server"
	"github.com/rocket-pool/smartnode/shared/types/api"
)

// ===============
// === Factory ===
// ===============

type oracleDaoMembersContextFactory struct {
	handler *OracleDaoHandler
}

func (f *oracleDaoMembersContextFactory) Create(args url.Values) (*oracleDaoMembersContext, error) {
	c := &oracleDaoMembersContext{
		handler: f.handler,
	}
	return c, nil
}

func (f *oracleDaoMembersContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterSingleStageRoute[*oracleDaoMembersContext, api.OracleDaoMembersData](
		router, "members", f, f.handler.serviceProvider,
	)
}

// ===============
// === Context ===
// ===============

type oracleDaoMembersContext struct {
	handler     *OracleDaoHandler
	rp          *rocketpool.RocketPool
	nodeAddress common.Address

	odaoMgr *oracle.OracleDaoManager
}

func (c *oracleDaoMembersContext) Initialize() error {
	sp := c.handler.serviceProvider
	c.rp = sp.GetRocketPool()
	c.nodeAddress, _ = sp.GetWallet().GetAddress()

	// Requirements
	err := sp.RequireEthClientSynced()
	if err != nil {
		return err
	}

	// Bindings
	c.odaoMgr, err = oracle.NewOracleDaoManager(c.rp)
	if err != nil {
		return fmt.Errorf("error creating Oracle DAO manager binding: %w", err)
	}
	return nil
}

func (c *oracleDaoMembersContext) GetState(mc *batch.MultiCaller) {
	c.odaoMgr.MemberCount.AddToQuery(mc)
}

func (c *oracleDaoMembersContext) PrepareData(data *api.OracleDaoMembersData, opts *bind.TransactOpts) error {
	// Get the member addresses
	addresses, err := c.odaoMgr.GetMemberAddresses(c.odaoMgr.MemberCount.Formatted(), nil)
	if err != nil {
		return fmt.Errorf("error getting Oracle DAO member addresses: %w", err)
	}

	// Get the member bindings
	members, err := c.odaoMgr.CreateMembersFromAddresses(addresses, true, nil)
	if err != nil {
		return fmt.Errorf("error creating Oracle DAO member bindings: %w", err)
	}

	for _, member := range members {
		memberDetails := api.OracleDaoMemberDetails{
			Address:          member.Address,
			Exists:           member.Exists.Get(),
			ID:               member.ID.Get(),
			Url:              member.Url.Get(),
			JoinedTime:       member.JoinedTime.Formatted(),
			LastProposalTime: member.LastProposalTime.Formatted(),
			RplBondAmount:    member.RplBondAmount.Get(),
		}
		data.Members = append(data.Members, memberDetails)
	}
	return nil
}
