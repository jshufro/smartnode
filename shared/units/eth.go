package units

import (
	"github.com/shopspring/decimal"
)

func NewEth(value uint64) *Eth {
	return &Eth{Decimal: decimal.NewFromUint64(value)}
}

func (e *Eth) ToWei() *Wei {
	return &Wei{Int: *e.Decimal.Shift(18).BigInt()}
}

func (e *Eth) ToEth() *Eth {
	return &Eth{e.Decimal.Copy()}
}

func (e *Eth) ToGwei() *Gwei {
	return &Gwei{e.Decimal.Shift(9)}
}

func (e *Eth) ToMilliEth() *MilliEth {
	return &MilliEth{e.Decimal.Shift(3)}
}
