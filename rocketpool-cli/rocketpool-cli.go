package main

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"github.com/mitchellh/go-homedir"
	"github.com/urfave/cli/v2"

	"github.com/rocket-pool/smartnode/rocketpool-cli/auction"
	"github.com/rocket-pool/smartnode/rocketpool-cli/faucet"
	"github.com/rocket-pool/smartnode/rocketpool-cli/minipool"
	"github.com/rocket-pool/smartnode/rocketpool-cli/network"
	"github.com/rocket-pool/smartnode/rocketpool-cli/node"
	"github.com/rocket-pool/smartnode/rocketpool-cli/odao"
	"github.com/rocket-pool/smartnode/rocketpool-cli/pdao"
	"github.com/rocket-pool/smartnode/rocketpool-cli/queue"
	"github.com/rocket-pool/smartnode/rocketpool-cli/security"
	"github.com/rocket-pool/smartnode/rocketpool-cli/service"
	"github.com/rocket-pool/smartnode/rocketpool-cli/utils"
	"github.com/rocket-pool/smartnode/rocketpool-cli/utils/context"
	"github.com/rocket-pool/smartnode/rocketpool-cli/wallet"
	"github.com/rocket-pool/smartnode/shared"
)

const (
	defaultConfigFolder string = ".rocketpool"
)

// Flags
var (
	allowRootFlag *cli.BoolFlag = &cli.BoolFlag{
		Name:    "allow-root",
		Aliases: []string{"r"},
		Usage:   "Allow rocketpool to be run as the root user",
	}
	configPathFlag *cli.StringFlag = &cli.StringFlag{
		Name:    "config-path",
		Aliases: []string{"c"},
		Usage:   "Directory to install and save all of Rocket Pool's configuration and data to",
	}
	apiSocketPathFlag *cli.StringFlag = &cli.StringFlag{
		Name:    "api-socket-path",
		Aliases: []string{"a"},
		Usage:   "The path of the socket file used to communicate with the Smart Node daemon. Only use this if you are running in Native Mode.",
	}
	maxFeeFlag *cli.Float64Flag = &cli.Float64Flag{
		Name:    "max-fee",
		Aliases: []string{"f"},
		Usage:   "The max fee (including the priority fee) you want a transaction to cost, in gwei. Use 0 to set it automatically based on network conditions.",
		Value:   0,
	}
	maxPriorityFeeFlag *cli.Float64Flag = &cli.Float64Flag{
		Name:    "max-priority-fee",
		Aliases: []string{"i"},
		Usage:   "The max priority fee you want a transaction to use, in gwei. Use 0 to set it automatically.",
		Value:   0,
	}
	nonceFlag *cli.StringFlag = &cli.StringFlag{
		Name:  "nonce",
		Usage: "Use this flag to explicitly specify the nonce that the next transaction should use, so it can override an existing 'stuck' transaction. If running a command that sends multiple transactions, the first will be given this nonce and the rest will be incremented sequentially.",
	}
	debugFlag *cli.BoolFlag = &cli.BoolFlag{
		Name:  "debug",
		Usage: "Enable debug printing of API commands",
	}
	secureSessionFlag *cli.BoolFlag = &cli.BoolFlag{
		Name:    "secure-session",
		Aliases: []string{"s"},
		Usage:   "Some commands may print sensitive information to your terminal. Use this flag when nobody can see your screen to allow sensitive data to be printed without prompting",
	}
)

// Run
func main() {
	// Add logo to application help template
	cli.AppHelpTemplate = fmt.Sprintf(`
______           _        _    ______           _ 
| ___ \         | |      | |   | ___ \         | |
| |_/ /___   ___| | _____| |_  | |_/ /__   ___ | |
|    // _ \ / __| |/ / _ \ __| |  __/ _ \ / _ \| |
| |\ \ (_) | (__|   <  __/ |_  | | | (_) | (_) | |
\_| \_\___/ \___|_|\_\___|\__| \_|  \___/ \___/|_|

%s`, cli.AppHelpTemplate)

	// Initialise application
	app := cli.NewApp()

	// Set application info
	app.Name = "rocketpool"
	app.Usage = "Smart Node CLI for Rocket Pool"
	app.Version = shared.RocketPoolVersion
	app.Authors = []*cli.Author{
		{
			Name:  "David Rugendyke",
			Email: "david@rocketpool.net",
		},
		{
			Name:  "Jake Pospischil",
			Email: "jake@rocketpool.net",
		},
		{
			Name:  "Joe Clapis",
			Email: "joe@rocketpool.net",
		},
		{
			Name:  "Kane Wallmann",
			Email: "kane@rocketpool.net",
		},
	}
	app.Copyright = "(c) 2024 Rocket Pool Pty Ltd"

	// Initialize app metadata
	app.Metadata = make(map[string]interface{})

	// Set application flags
	app.Flags = []cli.Flag{
		allowRootFlag,
		configPathFlag,
		apiSocketPathFlag,
		maxFeeFlag,
		maxPriorityFeeFlag,
		nonceFlag,
		debugFlag,
		secureSessionFlag,
	}

	// Set default paths for flags before parsing the provided values
	setDefaultPaths()

	// Register commands
	auction.RegisterCommands(app, "auction", []string{"a"})
	faucet.RegisterCommands(app, "faucet", []string{"f"})
	minipool.RegisterCommands(app, "minipool", []string{"m"})
	network.RegisterCommands(app, "network", []string{"e"})
	node.RegisterCommands(app, "node", []string{"n"})
	odao.RegisterCommands(app, "odao", []string{"o"})
	pdao.RegisterCommands(app, "pdao", []string{"p"})
	queue.RegisterCommands(app, "queue", []string{"q"})
	security.RegisterCommands(app, "security", []string{"c"})
	service.RegisterCommands(app, "service", []string{"s"})
	wallet.RegisterCommands(app, "wallet", []string{"w"})

	app.Before = func(c *cli.Context) error {
		// Check user ID
		if os.Getuid() == 0 && !c.Bool(allowRootFlag.Name) {
			fmt.Fprintln(os.Stderr, "rocketpool should not be run as root. Please try again without 'sudo'.")
			fmt.Fprintf(os.Stderr, "If you want to run rocketpool as root anyway, use the '--%s' option to override this warning.\n", allowRootFlag.Name)
			os.Exit(1)
		}

		err := validateFlags(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, err.Error())
			os.Exit(1)
		}
		return nil
	}

	// Run application
	fmt.Println()
	if err := app.Run(os.Args); err != nil {
		utils.PrettyPrintError(err)
	}
	fmt.Println()
}

// Set the default paths for various flags
func setDefaultPaths() {
	// Get the home directory
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Printf("Cannot get user's home directory: %w\n", err)
		os.Exit(1)
	}

	// Default config folder path
	defaultConfigPath := filepath.Join(homeDir, defaultConfigFolder)
	configPathFlag.Value = defaultConfigPath
}

// Validate the global flags
func validateFlags(c *cli.Context) error {
	snCtx := &context.SmartNodeContext{
		MaxFee:         c.Float64(maxFeeFlag.Name),
		MaxPriorityFee: c.Float64(maxPriorityFeeFlag.Name),
		DebugEnabled:   c.Bool(debugFlag.Name),
		SecureSession:  c.Bool(secureSessionFlag.Name),
	}

	// If set, validate custom nonce
	customNonce := c.String(nonceFlag.Name)
	if customNonce != "" {
		nonce, ok := big.NewInt(0).SetString(customNonce, 0)
		if !ok {
			return fmt.Errorf("Invalid nonce: %s\n", customNonce)
		}
		snCtx.Nonce = nonce
	}

	// Make sure the config directory exists
	configPath := c.String(configPathFlag.Name)
	path, err := homedir.Expand(strings.TrimSpace(configPath))
	if err != nil {
		return fmt.Errorf("error expanding config path [%s]: %w", configPath, err)
	}
	_, err = os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("Your configured Rocket Pool directory of [%s] does not exist.\nPlease follow the instructions at https://docs.rocketpool.net/guides/node/docker.html to install the Smartnode.", path)
	}
	snCtx.ConfigPath = configPath

	// Grab the daemon socket path; don't error out if it doesn't exist yet because this might be a new installation that hasn't configured and started it yet
	socketPath := c.String(apiSocketPathFlag.Name)
	path, err = homedir.Expand(strings.TrimSpace(socketPath))
	if err != nil {
		return fmt.Errorf("error expanding API socket path [%s]: %w", socketPath, err)
	}
	snCtx.ApiSocketPath = path

	// TODO: more here
	context.SetSmartnodeContext(c, snCtx)
	return nil
}
