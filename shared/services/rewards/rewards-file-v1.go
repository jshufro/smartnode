package rewards

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/goccy/go-json"
	"github.com/rocket-pool/rocketpool-go/types"
	"github.com/rocket-pool/rocketpool-go/utils/eth"
	"github.com/wealdtech/go-merkletree"
	"github.com/wealdtech/go-merkletree/keccak256"
)

type MinipoolPerformanceFile_v1 struct {
	Index               uint64                                                  `json:"index"`
	Network             string                                                  `json:"network"`
	StartTime           time.Time                                               `json:"startTime,omitempty"`
	EndTime             time.Time                                               `json:"endTime,omitempty"`
	ConsensusStartBlock uint64                                                  `json:"consensusStartBlock,omitempty"`
	ConsensusEndBlock   uint64                                                  `json:"consensusEndBlock,omitempty"`
	ExecutionStartBlock uint64                                                  `json:"executionStartBlock,omitempty"`
	ExecutionEndBlock   uint64                                                  `json:"executionEndBlock,omitempty"`
	MinipoolPerformance map[common.Address]*SmoothingPoolMinipoolPerformance_v1 `json:"minipoolPerformance"`
}

// Serialize a minipool performance file into bytes
func (f *MinipoolPerformanceFile_v1) Serialize() ([]byte, error) {
	return json.Marshal(f)
}

// Serialize a minipool performance file into bytes designed for human readability
func (f *MinipoolPerformanceFile_v1) SerializeHuman() ([]byte, error) {
	return json.MarshalIndent(f, "", "\t")
}

// Deserialize a minipool performance file from bytes
func (f *MinipoolPerformanceFile_v1) Deserialize(bytes []byte) error {
	return json.Unmarshal(bytes, &f)
}

// Get all of the minipool addresses with rewards in this file
// NOTE: the order of minipool addresses is not guaranteed to be stable, so don't rely on it
func (f *MinipoolPerformanceFile_v1) GetMinipoolAddresses() []common.Address {
	addresses := make([]common.Address, len(f.MinipoolPerformance))
	i := 0
	for address := range f.MinipoolPerformance {
		addresses[i] = address
		i++
	}
	return addresses
}

// Get a minipool's smoothing pool performance if it was present
func (f *MinipoolPerformanceFile_v1) GetSmoothingPoolPerformance(minipoolAddress common.Address) (ISmoothingPoolMinipoolPerformance, bool) {
	perf, exists := f.MinipoolPerformance[minipoolAddress]
	return perf, exists
}

// Minipool stats
type SmoothingPoolMinipoolPerformance_v1 struct {
	Pubkey                  string   `json:"pubkey"`
	StartSlot               uint64   `json:"startSlot,omitempty"`
	EndSlot                 uint64   `json:"endSlot,omitempty"`
	ActiveFraction          float64  `json:"activeFraction,omitempty"`
	SuccessfulAttestations  uint64   `json:"successfulAttestations"`
	MissedAttestations      uint64   `json:"missedAttestations"`
	ParticipationRate       float64  `json:"participationRate"`
	MissingAttestationSlots []uint64 `json:"missingAttestationSlots"`
	EthEarned               float64  `json:"ethEarned"`
}

func (p *SmoothingPoolMinipoolPerformance_v1) GetPubkey() (types.ValidatorPubkey, error) {
	return types.HexToValidatorPubkey(p.Pubkey)
}
func (p *SmoothingPoolMinipoolPerformance_v1) GetSuccessfulAttestationCount() uint64 {
	return p.SuccessfulAttestations
}
func (p *SmoothingPoolMinipoolPerformance_v1) GetMissedAttestationCount() uint64 {
	return p.MissedAttestations
}
func (p *SmoothingPoolMinipoolPerformance_v1) GetMissingAttestationSlots() []uint64 {
	return p.MissingAttestationSlots
}
func (p *SmoothingPoolMinipoolPerformance_v1) GetEthEarned() *big.Int {
	return eth.EthToWei(p.EthEarned)
}

// Node operator rewards
type NodeRewardsInfo_v1 struct {
	RewardNetwork                uint64        `json:"rewardNetwork"`
	CollateralRpl                *QuotedBigInt `json:"collateralRpl"`
	OracleDaoRpl                 *QuotedBigInt `json:"oracleDaoRpl"`
	SmoothingPoolEth             *QuotedBigInt `json:"smoothingPoolEth"`
	SmoothingPoolEligibilityRate float64       `json:"smoothingPoolEligibilityRate"`
	MerkleData                   []byte        `json:"-"`
	MerkleProof                  []string      `json:"merkleProof"`
}

func (i *NodeRewardsInfo_v1) GetRewardNetwork() uint64 {
	return i.RewardNetwork
}
func (i *NodeRewardsInfo_v1) GetCollateralRpl() *QuotedBigInt {
	return i.CollateralRpl
}
func (i *NodeRewardsInfo_v1) GetOracleDaoRpl() *QuotedBigInt {
	return i.OracleDaoRpl
}
func (i *NodeRewardsInfo_v1) GetSmoothingPoolEth() *QuotedBigInt {
	return i.SmoothingPoolEth
}
func (n *NodeRewardsInfo_v1) GetMerkleProof() ([]common.Hash, error) {
	proof := []common.Hash{}
	for _, proofLevel := range n.MerkleProof {
		proof = append(proof, common.HexToHash(proofLevel))
	}
	return proof, nil
}

// JSON struct for a complete rewards file
type RewardsFile_v1 struct {
	*RewardsFileHeader
	NodeRewards             map[common.Address]*NodeRewardsInfo_v1 `json:"nodeRewards"`
	MinipoolPerformanceFile MinipoolPerformanceFile_v1             `json:"-"`
}

// Serialize a rewards file into bytes
func (f *RewardsFile_v1) Serialize() ([]byte, error) {
	return json.Marshal(f)
}

// Deserialize a rewards file from bytes
func (f *RewardsFile_v1) Deserialize(bytes []byte) error {
	return json.Unmarshal(bytes, &f)
}

// Get the rewards file version
func (f *RewardsFile_v1) GetRewardsFileVersion() rewardsFileVersion {
	return rewardsFileVersionOne
}

// Get the rewards file index
func (f *RewardsFile_v1) GetIndex() uint64 {
	return f.RewardsFileHeader.Index
}

// Get the TotalNodeWeight (only added in v3)
func (f *RewardsFile_v1) GetTotalNodeWeight() *big.Int {
	return nil
}

// Get the merkle root
func (f *RewardsFile_v1) GetMerkleRoot() string {
	return f.RewardsFileHeader.MerkleRoot
}

// Get network rewards for a specific network
func (f *RewardsFile_v1) GetNetworkRewards(network uint64) *NetworkRewardsInfo {
	return f.RewardsFileHeader.NetworkRewards[network]
}

// Get the number of intervals that have passed
func (f *RewardsFile_v1) GetIntervalsPassed() uint64 {
	return f.RewardsFileHeader.IntervalsPassed
}

// Get the total RPL sent to the pDAO
func (f *RewardsFile_v1) GetTotalProtocolDaoRpl() *big.Int {
	return &f.RewardsFileHeader.TotalRewards.ProtocolDaoRpl.Int
}

// Get the total RPL sent to the pDAO
func (f *RewardsFile_v1) GetTotalOracleDaoRpl() *big.Int {
	return &f.RewardsFileHeader.TotalRewards.TotalOracleDaoRpl.Int
}

// Get the total Eth sent to pool stakers from the SP
func (f *RewardsFile_v1) GetTotalPoolStakerSmoothingPoolEth() *big.Int {
	return &f.RewardsFileHeader.TotalRewards.PoolStakerSmoothingPoolEth.Int
}

// Get the total rpl sent to stakers
func (f *RewardsFile_v1) GetTotalCollateralRpl() *big.Int {
	return &f.RewardsFileHeader.TotalRewards.TotalCollateralRpl.Int
}

// Get the total smoothing pool eth sent to node operators
func (f *RewardsFile_v1) GetTotalNodeOperatorSmoothingPoolEth() *big.Int {
	return &f.RewardsFileHeader.TotalRewards.NodeOperatorSmoothingPoolEth.Int
}

// Get the the execution end block
func (f *RewardsFile_v1) GetExecutionEndBlock() uint64 {
	return f.RewardsFileHeader.ExecutionEndBlock
}

// Get the the consensus end block
func (f *RewardsFile_v1) GetConsensusEndBlock() uint64 {
	return f.RewardsFileHeader.ConsensusEndBlock
}

// Get all of the node addresses with rewards in this file
// NOTE: the order of node addresses is not guaranteed to be stable, so don't rely on it
func (f *RewardsFile_v1) GetNodeAddresses() []common.Address {
	addresses := make([]common.Address, len(f.NodeRewards))
	i := 0
	for address := range f.NodeRewards {
		addresses[i] = address
		i++
	}
	return addresses
}

// Get info about a node's rewards
func (f *RewardsFile_v1) GetNodeRewardsInfo(address common.Address) (INodeRewardsInfo, bool) {
	rewards, exists := f.NodeRewards[address]
	return rewards, exists
}

// Sets the CID of the minipool performance file corresponding to this rewards file
func (f *RewardsFile_v1) SetMinipoolPerformanceFileCID(cid string) {
	f.MinipoolPerformanceFileCID = cid
}

// Generates a merkle tree from the provided rewards map
func (f *RewardsFile_v1) generateMerkleTree() error {
	// Generate the leaf data for each node
	totalData := make([][]byte, 0, len(f.NodeRewards))
	for address, rewardsForNode := range f.NodeRewards {
		// Ignore nodes that didn't receive any rewards
		if rewardsForNode.CollateralRpl.Cmp(common.Big0) == 0 && rewardsForNode.OracleDaoRpl.Cmp(common.Big0) == 0 && rewardsForNode.SmoothingPoolEth.Cmp(common.Big0) == 0 {
			continue
		}

		// Node data is address[20] :: network[32] :: RPL[32] :: ETH[32]
		nodeData := make([]byte, 0, 20+32*3)

		// Node address
		addressBytes := address.Bytes()
		nodeData = append(nodeData, addressBytes...)

		// Node network
		network := big.NewInt(0).SetUint64(rewardsForNode.RewardNetwork)
		networkBytes := make([]byte, 32)
		network.FillBytes(networkBytes)
		nodeData = append(nodeData, networkBytes...)

		// RPL rewards
		rplRewards := big.NewInt(0)
		rplRewards.Add(&rewardsForNode.CollateralRpl.Int, &rewardsForNode.OracleDaoRpl.Int)
		rplRewardsBytes := make([]byte, 32)
		rplRewards.FillBytes(rplRewardsBytes)
		nodeData = append(nodeData, rplRewardsBytes...)

		// ETH rewards
		ethRewardsBytes := make([]byte, 32)
		rewardsForNode.SmoothingPoolEth.FillBytes(ethRewardsBytes)
		nodeData = append(nodeData, ethRewardsBytes...)

		// Assign it to the node rewards tracker and add it to the leaf data slice
		rewardsForNode.MerkleData = nodeData
		totalData = append(totalData, nodeData)
	}

	// Generate the tree
	tree, err := merkletree.NewUsing(totalData, keccak256.New(), false, true)
	if err != nil {
		return fmt.Errorf("error generating Merkle Tree: %w", err)
	}

	// Generate the proofs for each node
	for address, rewardsForNode := range f.NodeRewards {
		// Get the proof
		proof, err := tree.GenerateProof(rewardsForNode.MerkleData, 0)
		if err != nil {
			return fmt.Errorf("error generating proof for node %s: %w", address.Hex(), err)
		}

		// Convert the proof into hex strings
		proofStrings := make([]string, len(proof.Hashes))
		for i, hash := range proof.Hashes {
			proofStrings[i] = fmt.Sprintf("0x%s", hex.EncodeToString(hash))
		}

		// Assign the hex strings to the node rewards struct
		rewardsForNode.MerkleProof = proofStrings
	}

	f.MerkleTree = tree
	f.MerkleRoot = common.BytesToHash(tree.Root()).Hex()
	return nil
}
