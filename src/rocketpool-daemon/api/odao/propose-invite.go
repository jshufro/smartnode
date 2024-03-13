package odao

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/gorilla/mux"
	batch "github.com/rocket-pool/batch-query"
	"github.com/rocket-pool/node-manager-core/eth"
	"github.com/rocket-pool/rocketpool-go/dao/oracle"
	"github.com/rocket-pool/rocketpool-go/rocketpool"

	"github.com/rocket-pool/node-manager-core/api/server"
	"github.com/rocket-pool/node-manager-core/utils/input"
	"github.com/rocket-pool/smartnode/shared/types/api"
	"github.com/rocket-pool/smartnode/shared/utils"
)

// ===============
// === Factory ===
// ===============

type oracleDaoProposeInviteContextFactory struct {
	handler *OracleDaoHandler
}

func (f *oracleDaoProposeInviteContextFactory) Create(args url.Values) (*oracleDaoProposeInviteContext, error) {
	c := &oracleDaoProposeInviteContext{
		handler: f.handler,
	}
	inputErrs := []error{
		server.ValidateArg("address", args, input.ValidateAddress, &c.address),
		server.ValidateArg("id", args, utils.ValidateDAOMemberID, &c.id),
		server.GetStringFromVars("url", args, &c.url),
	}
	return c, errors.Join(inputErrs...)
}

func (f *oracleDaoProposeInviteContextFactory) RegisterRoute(router *mux.Router) {
	server.RegisterSingleStageRoute[*oracleDaoProposeInviteContext, api.OracleDaoProposeInviteData](
		router, "propose-invite", f, f.handler.serviceProvider.ServiceProvider,
	)
}

// ===============
// === Context ===
// ===============

type oracleDaoProposeInviteContext struct {
	handler     *OracleDaoHandler
	rp          *rocketpool.RocketPool
	nodeAddress common.Address

	address    common.Address
	id         string
	url        string
	odaoMember *oracle.OracleDaoMember
	candidate  *oracle.OracleDaoMember
	oSettings  *oracle.OracleDaoSettings
	odaoMgr    *oracle.OracleDaoManager
}

func (c *oracleDaoProposeInviteContext) Initialize() error {
	sp := c.handler.serviceProvider
	c.rp = sp.GetRocketPool()
	c.nodeAddress, _ = sp.GetWallet().GetAddress()

	// Requirements
	err := sp.RequireOnOracleDao(c.handler.context)
	if err != nil {
		return err
	}

	// Bindings
	c.odaoMember, err = oracle.NewOracleDaoMember(c.rp, c.nodeAddress)
	if err != nil {
		return fmt.Errorf("error creating oracle DAO member binding: %w", err)
	}
	c.candidate, err = oracle.NewOracleDaoMember(c.rp, c.address)
	if err != nil {
		return fmt.Errorf("error creating candidate oracle DAO member binding: %w", err)
	}
	c.odaoMgr, err = oracle.NewOracleDaoManager(c.rp)
	if err != nil {
		return fmt.Errorf("error creating Oracle DAO manager binding: %w", err)
	}
	c.oSettings = c.odaoMgr.Settings
	return nil
}

func (c *oracleDaoProposeInviteContext) GetState(mc *batch.MultiCaller) {
	eth.AddQueryablesToMulticall(mc,
		c.odaoMember.LastProposalTime,
		c.oSettings.Proposal.CooldownTime,
		c.candidate.Exists,
	)
}

func (c *oracleDaoProposeInviteContext) PrepareData(data *api.OracleDaoProposeInviteData, opts *bind.TransactOpts) error {
	// Get the timestamp of the latest block
	latestHeader, err := c.rp.Client.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("error getting latest block header: %w", err)
	}
	currentTime := time.Unix(int64(latestHeader.Time), 0)
	cooldownTime := c.oSettings.Proposal.CooldownTime.Formatted()

	// Check proposal details
	data.ProposalCooldownActive = isProposalCooldownActive(cooldownTime, c.odaoMember.LastProposalTime.Formatted(), currentTime)
	data.MemberAlreadyExists = c.candidate.Exists.Get()
	data.CanPropose = !(data.ProposalCooldownActive || data.MemberAlreadyExists)

	// Get the tx
	if data.CanPropose && opts != nil {
		message := fmt.Sprintf("invite %s (%s)", c.id, c.url)
		txInfo, err := c.odaoMgr.ProposeInviteMember(message, c.address, c.id, c.url, opts)
		if err != nil {
			return fmt.Errorf("error getting TX info for ProposeInviteMember: %w", err)
		}
		data.TxInfo = txInfo
	}
	return nil
}
