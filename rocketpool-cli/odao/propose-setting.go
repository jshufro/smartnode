package odao

import (
	"fmt"
	"math/big"
	"time"

	"github.com/rocket-pool/rocketpool-go/dao/oracle"
	"github.com/rocket-pool/rocketpool-go/rocketpool"
	"github.com/urfave/cli/v2"

	"github.com/rocket-pool/smartnode/rocketpool-cli/utils"
	"github.com/rocket-pool/smartnode/rocketpool-cli/utils/client"
	"github.com/rocket-pool/smartnode/rocketpool-cli/utils/tx"
)

func proposeSetting[ValueType utils.SettingType](c *cli.Context, contract rocketpool.ContractName, setting oracle.SettingName, value ValueType) error {
	// Get RP client
	rp, err := client.NewClientFromCtx(c).WithReady()
	if err != nil {
		return err
	}

	// Serialize the value
	var valueString string
	switch trueValue := any(value).(type) {
	case *big.Int:
		valueString = trueValue.String()
	case time.Duration:
		valueString = fmt.Sprint(uint64(trueValue.Seconds()))
	default:
		panic("unknown setting type")
	}

	// Build the TX
	response, err := rp.Api.ODao.ProposeSetting(contract, setting, valueString)
	if err != nil {
		return err
	}

	// Verify
	if !response.Data.CanPropose {
		fmt.Println("Cannot propose setting update:")
		if response.Data.UnknownSetting {
			fmt.Sprintf("Unknown setting '%s' on contract '%s'.\n", setting, contract)
		}
		if response.Data.ProposalCooldownActive {
			fmt.Println("The node must wait for the proposal cooldown period to pass before making another proposal.")
		}
		return nil
	}

	// Run the TX
	err = tx.HandleTx(c, rp, response.Data.TxInfo,
		"Are you sure you want to submit this proposal?",
		"setting update",
		"Proposing Oracle DAO setting update...",
	)

	// Log & return
	fmt.Printf("Successfully proposed setting '%s.%s' to '%s'.\n", contract, setting, value)
	return nil
}
