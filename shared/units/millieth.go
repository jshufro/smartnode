package units

func (m MilliEth) ToWei() Wei {
	return Wei{m.Decimal.Shift(milliEthExp - weiExp).Round(weiExp)}
}

func (m MilliEth) ToEth() Eth {
	return Eth{m.Decimal.Shift(milliEthExp - ethExp).Round(ethExp)}
}

func (m MilliEth) ToGwei() Gwei {
	return Gwei{m.Decimal.Shift(milliEthExp - gweiExp).Round(gweiExp)}
}

func (m MilliEth) ToMilliEth() MilliEth {
	return MilliEth{m.Decimal.Round(milliEthExp)}
}
