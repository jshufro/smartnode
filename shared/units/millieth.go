package units

func (m *MilliEth) ToWei() *Wei {
	return &Wei{Int: *m.Decimal.Shift(15).BigInt()}
}

func (m *MilliEth) ToEth() *Eth {
	return &Eth{m.Decimal.Shift(-3)}
}

func (m *MilliEth) ToGwei() *Gwei {
	return &Gwei{m.Decimal.Shift(6)}
}

func (m *MilliEth) ToMilliEth() *MilliEth {
	return &MilliEth{m.Decimal.Copy()}
}
