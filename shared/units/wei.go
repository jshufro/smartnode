package units

import (
	"math/big"

	"github.com/shopspring/decimal"
)

var (
	OneEth    Wei
	OneEthBig *big.Int
)

func init() {
	OneEth = Wei{Int: *big.NewInt(1e18)}
	OneEthBig = &OneEth.Int
}

func NewWei(value *big.Int) *Wei {
	if value == nil {
		return nil
	}

	return &Wei{Int: *value}
}

// MarshalJSON encodes Wei as a JSON integer. Embedded big.Int only provides a
// pointer-receiver MarshalJSON, which encoding/json skips for non-addressable
// values and would otherwise emit {}.
func (w Wei) MarshalJSON() ([]byte, error) {
	return w.Int.MarshalJSON()
}

func (w *Wei) UnmarshalJSON(data []byte) error {
	return w.Int.UnmarshalJSON(data)
}

// MarshalText encodes Wei as a decimal integer string. Same pointer-receiver
// limitation as MarshalJSON for encoding.TextMarshaler satisfaction by value.
func (w Wei) MarshalText() ([]byte, error) {
	return w.Int.MarshalText()
}

func (w *Wei) UnmarshalText(text []byte) error {
	return w.Int.UnmarshalText(text)
}

func (w Wei) AppendText(b []byte) ([]byte, error) {
	return w.Int.AppendText(b)
}

func (w *Wei) ToWei() *Wei {
	out := new(Wei)
	out.Set(&w.Int)
	return out
}

func (w *Wei) ToEth() *Eth {
	return &Eth{decimal.NewFromBigInt(&w.Int, -18)}
}

func (w *Wei) ToGwei() *Gwei {
	return &Gwei{decimal.NewFromBigInt(&w.Int, -9)}
}

func (w *Wei) ToMilliEth() *MilliEth {
	return &MilliEth{decimal.NewFromBigInt(&w.Int, -15)}
}

// Convenience method to set the value of a Wei from a big.Int, useful for
// integrating with libraries i.e. abigen that use big.Int.
func (w *Wei) SetBig(value *big.Int) *Wei {
	w.Int.Set(value)
	return w
}

// Convenience method to convert to big for external libraries
func (w *Wei) Big() *big.Int {
	return &w.Int
}
