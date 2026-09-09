package units

import (
	"math"
	"math/big"
	"strconv"
)

// Conversion factors
const (
	weiPerEth      float64 = 1e18
	weiPerGwei     float64 = 1e9
	weiPerMilliEth float64 = 1e15
	gweiPerEth     float64 = 1e9
)

// Convert wei to eth
func WeiToEth(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	var weiFloat big.Float
	var eth big.Float
	weiFloat.SetInt(wei)
	eth.Quo(&weiFloat, big.NewFloat(weiPerEth))
	eth64, _ := eth.Float64()
	return eth64
}

// Convert eth to wei
func EthToWei(eth float64) *big.Int {
	var ethFloat big.Float
	var weiFloat big.Float
	var wei big.Int
	ethFloat.SetString(strconv.FormatFloat(eth, 'f', -1, 64))
	weiFloat.Mul(&ethFloat, big.NewFloat(weiPerEth))
	weiFloat.Int(&wei)
	return &wei
}

// Convert wei to gigawei
func WeiToGwei(wei *big.Int) float64 {
	if wei == nil {
		return 0
	}
	var weiFloat big.Float
	var gwei big.Float
	weiFloat.SetInt(wei)
	gwei.Quo(&weiFloat, big.NewFloat(weiPerGwei))
	gwei64, _ := gwei.Float64()
	return gwei64
}

func WeiToGweiBig(wei *big.Int) *big.Int {
	if wei == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Div(wei, big.NewInt(int64(weiPerGwei)))
}

func GweiUintToWei(gwei uint64) *big.Int {
	out := new(big.Int).SetUint64(gwei)
	return out.Mul(out, big.NewInt(int64(weiPerGwei)))
}

// Convert gigawei to wei
func GweiToWei(gwei float64) *big.Int {
	var gweiFloat big.Float
	var weiFloat big.Float
	var wei big.Int
	gweiFloat.SetString(strconv.FormatFloat(gwei, 'f', -1, 64))
	weiFloat.Mul(&gweiFloat, big.NewFloat(weiPerGwei))
	weiFloat.Int(&wei)
	return &wei
}

func GweiToEth(gwei float64) float64 {
	return gwei / gweiPerEth
}

// Convert milliEth to wei
func MilliEthToWei(milliEth float64) *big.Int {
	var milliEthFloat big.Float
	var weiFloat big.Float
	var wei big.Int
	milliEthFloat.SetString(strconv.FormatFloat(milliEth, 'f', -1, 64))
	weiFloat.Mul(&milliEthFloat, big.NewFloat(weiPerMilliEth))
	weiFloat.Int(&wei)
	return &wei
}

// Converts float amount to big.Int considering a token's decimals
func EthToWeiWithDecimals(amountRaw float64, decimals uint8) *big.Int {
	var ethFloat big.Float
	var weiFloat big.Float
	var wei big.Int
	ethFloat.SetString(strconv.FormatFloat(amountRaw, 'f', -1, 64))
	weiFloat.Mul(&ethFloat, big.NewFloat(math.Pow(10, float64(decimals))))
	weiFloat.Int(&wei)
	return &wei
}

// Converts big.Int to float64 considering a token's decimals
func WeiToEthWithDecimals(amount *big.Int, decimals uint8) float64 {
	if amount == nil {
		return 0
	}
	var weiFloat big.Float
	var eth big.Float
	weiFloat.SetInt(amount)
	eth.Quo(&weiFloat, big.NewFloat(math.Pow(10, float64(decimals))))
	eth64, _ := eth.Float64()
	return eth64
}
