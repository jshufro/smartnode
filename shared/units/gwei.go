package units

import (
	"github.com/shopspring/decimal"
)

func NewGwei(value uint64) Gwei {
	return Gwei{
		Decimal: decimal.NewFromUint64(value),
	}
}

func (g Gwei) ToWei() Wei {
	return Wei{g.Decimal.Shift(gweiExp - weiExp).Round(weiExp)}
}

func (g Gwei) ToEth() Eth {
	return Eth{g.Decimal.Shift(gweiExp - ethExp).Round(ethExp)}
}

func (g Gwei) ToGwei() Gwei {
	return Gwei{g.Decimal.Round(gweiExp)}
}

func (g Gwei) ToMilliEth() MilliEth {
	return MilliEth{g.Decimal.Shift(gweiExp - milliEthExp).Round(milliEthExp)}
}
