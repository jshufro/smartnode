package units

import (
	"github.com/shopspring/decimal"
)

func NewGwei(value uint64) *Gwei {
	return &Gwei{
		Decimal: decimal.NewFromUint64(value),
	}
}

func (g *Gwei) ToWei() *Wei {
	return &Wei{Int: *g.Decimal.Shift(9).BigInt()}
}

func (g *Gwei) ToEth() *Eth {
	return &Eth{g.Decimal.Shift(-9)}
}

func (g *Gwei) ToGwei() *Gwei {
	return &Gwei{g.Decimal.Copy()}
}

func (g *Gwei) ToMilliEth() *MilliEth {
	return &MilliEth{g.Decimal.Shift(-6)}
}
