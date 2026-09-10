package units

import (
	"github.com/shopspring/decimal"
)

// Exponents relative to wei (also the max fractional digits for each unit).
const (
	weiExp      int32 = 0
	gweiExp     int32 = 9
	milliEthExp int32 = 15
	ethExp      int32 = 18
)

// Wei is the fundamental unit of value, and is always integral.
type Wei struct {
	decimal.Decimal
}

// Eth is 1e18 of Wei.
type Eth struct {
	decimal.Decimal
}

// Gwei is 1e9 of Wei.
type Gwei struct {
	decimal.Decimal
}

// MilliEth is 1e15 of Wei.
type MilliEth struct {
	decimal.Decimal
}

// Unit is a common interface for any unit of value
type Unit interface {
	ToWei() Wei
	ToEth() Eth
	ToGwei() Gwei
	ToMilliEth() MilliEth
}

// Type assertions that each unit implements the Unit interface
var _ Unit = Wei{}
var _ Unit = Eth{}
var _ Unit = Gwei{}
var _ Unit = MilliEth{}
