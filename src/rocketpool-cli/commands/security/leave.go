package security

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/rocket-pool/smartnode/rocketpool-cli/client"
	"github.com/rocket-pool/smartnode/rocketpool-cli/utils/tx"
)

func leave(c *cli.Context) error {
	// Get RP client
	rp, err := client.NewClientFromCtx(c).WithReady()
	if err != nil {
		return err
	}

	// Build the TX
	response, err := rp.Api.Security.Leave()
	if err != nil {
		return err
	}

	// Verify
	if !response.Data.CanLeave {
		fmt.Println("Cannot leave the security council:")
		if response.Data.ProposalExpired {
			fmt.Println("The proposal for you to leave the Security Council does not exist or has expired.")
		}
		if response.Data.IsNotMember {
			fmt.Println("You are not a member of the Security Council.")
		}
		return nil
	}

	// Run the TX
	err = tx.HandleTx(c, rp, response.Data.TxInfo,
		"Are you sure you want to leave the Security Council? This action cannot be undone!",
		"leaving Security Council",
		"Leaving the Security Council...",
	)
	if err != nil {
		return err
	}

	// Log & return
	fmt.Println("Successfully left the security council.")
	return nil
}