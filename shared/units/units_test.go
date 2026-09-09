package units

import (
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
)

func pow10(exp int64) *big.Int {
	return new(big.Int).Exp(big.NewInt(10), big.NewInt(exp), nil)
}

func newWei(v *big.Int) *Wei {
	w := new(Wei)
	w.Set(v)
	return w
}

func TestUnitConversions(t *testing.T) {
	oneWei := newWei(big.NewInt(1))
	oneGwei := &Gwei{Decimal: decimal.NewFromInt(1)}
	oneMilliEth := &MilliEth{Decimal: decimal.NewFromInt(1)}
	oneEth := &Eth{Decimal: decimal.NewFromInt(1)}

	tests := []struct {
		name string
		from Unit
		want map[string]*big.Int // expected wei amount after ToWei()
	}{
		{
			name: "1 wei",
			from: oneWei,
			want: map[string]*big.Int{
				"wei":      big.NewInt(1),
				"gwei":     big.NewInt(1),
				"milliEth": big.NewInt(1),
				"eth":      big.NewInt(1),
			},
		},
		{
			name: "1 gwei",
			from: oneGwei,
			want: map[string]*big.Int{
				"wei":      pow10(9),
				"gwei":     pow10(9),
				"milliEth": pow10(9),
				"eth":      pow10(9),
			},
		},
		{
			name: "1 milliEth",
			from: oneMilliEth,
			want: map[string]*big.Int{
				"wei":      pow10(15),
				"gwei":     pow10(15),
				"milliEth": pow10(15),
				"eth":      pow10(15),
			},
		},
		{
			name: "1 eth",
			from: oneEth,
			want: map[string]*big.Int{
				"wei":      pow10(18),
				"gwei":     pow10(18),
				"milliEth": pow10(18),
				"eth":      pow10(18),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := map[string]*Wei{
				"wei":      tt.from.ToWei(),
				"gwei":     tt.from.ToGwei().ToWei(),
				"milliEth": tt.from.ToMilliEth().ToWei(),
				"eth":      tt.from.ToEth().ToWei(),
			}
			for dest, wantWei := range tt.want {
				if got[dest].Cmp(wantWei) != 0 {
					t.Errorf("%s -> %s -> wei = %s, want %s", tt.name, dest, got[dest], wantWei)
				}
			}
		})
	}
}

func TestUnitExactValues(t *testing.T) {
	oneEth := &Eth{Decimal: decimal.NewFromInt(1)}

	if !oneEth.ToGwei().Equal(decimal.NewFromInt(1e9)) {
		t.Errorf("1 eth -> gwei = %s, want 1e9", oneEth.ToGwei())
	}
	if !oneEth.ToMilliEth().Equal(decimal.NewFromInt(1000)) {
		t.Errorf("1 eth -> milliEth = %s, want 1000", oneEth.ToMilliEth())
	}

	oneGwei := &Gwei{Decimal: decimal.NewFromInt(1)}
	if !oneGwei.ToEth().Equal(decimal.RequireFromString("0.000000001")) {
		t.Errorf("1 gwei -> eth = %s, want 1e-9", oneGwei.ToEth())
	}
	if !oneGwei.ToMilliEth().Equal(decimal.RequireFromString("0.000001")) {
		t.Errorf("1 gwei -> milliEth = %s, want 1e-6", oneGwei.ToMilliEth())
	}

	oneMilli := &MilliEth{Decimal: decimal.NewFromInt(1)}
	if !oneMilli.ToEth().Equal(decimal.RequireFromString("0.001")) {
		t.Errorf("1 milliEth -> eth = %s, want 0.001", oneMilli.ToEth())
	}
	if !oneMilli.ToGwei().Equal(decimal.NewFromInt(1e6)) {
		t.Errorf("1 milliEth -> gwei = %s, want 1e6", oneMilli.ToGwei())
	}

	oneWei := newWei(big.NewInt(1))
	if !oneWei.ToEth().Equal(decimal.RequireFromString("0.000000000000000001")) {
		t.Errorf("1 wei -> eth = %s, want 1e-18", oneWei.ToEth())
	}
	if !oneWei.ToGwei().Equal(decimal.RequireFromString("0.000000001")) {
		t.Errorf("1 wei -> gwei = %s, want 1e-9", oneWei.ToGwei())
	}
	if !oneWei.ToMilliEth().Equal(decimal.RequireFromString("0.000000000000001")) {
		t.Errorf("1 wei -> milliEth = %s, want 1e-15", oneWei.ToMilliEth())
	}
}

func TestUnitRoundTrips(t *testing.T) {
	starters := []struct {
		name string
		u    Unit
	}{
		{"wei", newWei(pow10(18))},
		{"gwei", &Gwei{Decimal: decimal.NewFromInt(1e9)}},
		{"milliEth", &MilliEth{Decimal: decimal.NewFromInt(1000)}},
		{"eth", &Eth{Decimal: decimal.NewFromInt(1)}},
	}

	for _, s := range starters {
		t.Run(s.name, func(t *testing.T) {
			want := s.u.ToWei()
			via := []Unit{
				s.u.ToWei(),
				s.u.ToGwei(),
				s.u.ToMilliEth(),
				s.u.ToEth(),
			}
			for _, v := range via {
				if got := v.ToWei(); got.Cmp(&want.Int) != 0 {
					t.Errorf("%s round-trip via %T -> wei = %s, want %s", s.name, v, got, want)
				}
				if got := v.ToEth().ToWei(); got.Cmp(&want.Int) != 0 {
					t.Errorf("%s round-trip via %T.ToEth() -> wei = %s, want %s", s.name, v, got, want)
				}
				if got := v.ToGwei().ToWei(); got.Cmp(&want.Int) != 0 {
					t.Errorf("%s round-trip via %T.ToGwei() -> wei = %s, want %s", s.name, v, got, want)
				}
				if got := v.ToMilliEth().ToWei(); got.Cmp(&want.Int) != 0 {
					t.Errorf("%s round-trip via %T.ToMilliEth() -> wei = %s, want %s", s.name, v, got, want)
				}
			}
		})
	}
}

func TestUnitIdentityCopies(t *testing.T) {
	eth := &Eth{Decimal: decimal.NewFromInt(42)}
	gwei := &Gwei{Decimal: decimal.NewFromInt(42)}
	milli := &MilliEth{Decimal: decimal.NewFromInt(42)}
	wei := newWei(big.NewInt(42))

	if !eth.ToEth().Equal(eth.Decimal) {
		t.Error("Eth.ToEth() should equal original")
	}
	if !gwei.ToGwei().Equal(gwei.Decimal) {
		t.Error("Gwei.ToGwei() should equal original")
	}
	if !milli.ToMilliEth().Equal(milli.Decimal) {
		t.Error("MilliEth.ToMilliEth() should equal original")
	}
	if wei.ToWei().Cmp(&wei.Int) != 0 {
		t.Error("Wei.ToWei() should equal original")
	}

	// Copies should not share mutable state with the original.
	copied := eth.ToEth()
	copied.Decimal = decimal.NewFromInt(1)
	if eth.Equal(decimal.NewFromInt(1)) {
		t.Error("Eth.ToEth() should return a copy")
	}
}
