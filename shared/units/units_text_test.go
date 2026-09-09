package units

import (
	"bytes"
	"encoding"
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
)

func TestUnitTextRoundTrip(t *testing.T) {
	preciseEth := "1234567890.123456789012345678"
	preciseGwei := "9876543210.987654321"
	preciseMilli := "111222333444.555666777"
	preciseWei := "123456789012345678901234567890" // > 2^53

	t.Run("Eth", func(t *testing.T) {
		in := Eth{Decimal: decimal.RequireFromString(preciseEth)}
		assertTextMarshaler(t, in)

		raw, err := in.MarshalText()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(raw) != preciseEth {
			t.Fatalf("marshal = %q, want %q", raw, preciseEth)
		}

		var out Eth
		assertTextUnmarshaler(t, &out)
		if err := out.UnmarshalText(raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip = %s, want %s", out, in)
		}
	})

	t.Run("Gwei", func(t *testing.T) {
		in := Gwei{Decimal: decimal.RequireFromString(preciseGwei)}
		assertTextMarshaler(t, in)

		raw, err := in.MarshalText()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(raw) != preciseGwei {
			t.Fatalf("marshal = %q, want %q", raw, preciseGwei)
		}

		var out Gwei
		assertTextUnmarshaler(t, &out)
		if err := out.UnmarshalText(raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip = %s, want %s", out, in)
		}
	})

	t.Run("MilliEth", func(t *testing.T) {
		in := MilliEth{Decimal: decimal.RequireFromString(preciseMilli)}
		assertTextMarshaler(t, in)

		raw, err := in.MarshalText()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(raw) != preciseMilli {
			t.Fatalf("marshal = %q, want %q", raw, preciseMilli)
		}

		var out MilliEth
		assertTextUnmarshaler(t, &out)
		if err := out.UnmarshalText(raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip = %s, want %s", out, in)
		}
	})

	t.Run("Wei", func(t *testing.T) {
		in := *newWei(mustBigInt(preciseWei))
		assertTextMarshaler(t, in)

		raw, err := in.MarshalText()
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(raw) != preciseWei {
			t.Fatalf("marshal = %q, want %q", raw, preciseWei)
		}

		var out Wei
		assertTextUnmarshaler(t, &out)
		if err := out.UnmarshalText(raw); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if in.Cmp(&out.Int) != 0 {
			t.Fatalf("round-trip = %s, want %s", &out.Int, &in.Int)
		}
	})
}

func TestUnitTextDoesNotUseFloat(t *testing.T) {
	const amount = "0.123456789012345678"
	in := Eth{Decimal: decimal.RequireFromString(amount)}

	raw, err := in.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != amount {
		t.Fatalf("marshal = %q, want %q", raw, amount)
	}

	asFloat, err := decimal.NewFromString(amount)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Sanity: the discriminating float loss still holds for this amount.
	if decimal.NewFromFloat(asFloat.InexactFloat64()).Equal(in.Decimal) {
		t.Fatal("expected float64 path to lose precision; test value is not discriminating enough")
	}

	var out Eth
	if err := out.UnmarshalText(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !out.Equal(in.Decimal) {
		t.Fatalf("text path lost precision: got %s, want %s", out, in)
	}
}

func TestWeiTextPreservesBeyondFloatMantissa(t *testing.T) {
	in := *newWei(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1)))

	raw, err := in.MarshalText()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != in.String() {
		t.Fatalf("marshal = %q, want %q", raw, in.String())
	}

	floatApprox, _ := new(big.Float).SetInt(&in.Int).Float64()
	if decimal.NewFromFloat(floatApprox).BigInt().Cmp(&in.Int) == 0 {
		t.Fatal("expected float64 path to lose precision for 2^53+1")
	}

	var out Wei
	if err := out.UnmarshalText(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if in.Cmp(&out.Int) != 0 {
		t.Fatalf("text path lost precision: got %s, want %s", &out.Int, &in.Int)
	}
}

func TestWeiAppendText(t *testing.T) {
	in := *newWei(mustBigInt("123456789012345678901234567890"))
	prefix := []byte("amount=")

	got, err := in.AppendText(prefix)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	want := append([]byte(nil), prefix...)
	want = append(want, []byte(in.String())...)
	if !bytes.Equal(got, want) {
		t.Fatalf("AppendText = %q, want %q", got, want)
	}

	// Original prefix buffer must not be required to stay unmodified beyond len,
	// but the returned slice should start with the prefix contents.
	if !bytes.HasPrefix(got, prefix) {
		t.Fatalf("AppendText missing prefix: %q", got)
	}
}

func assertTextMarshaler(t *testing.T, v any) {
	t.Helper()
	if _, ok := v.(encoding.TextMarshaler); !ok {
		t.Fatalf("%T does not implement encoding.TextMarshaler by value", v)
	}
}

func assertTextUnmarshaler(t *testing.T, v any) {
	t.Helper()
	if _, ok := v.(encoding.TextUnmarshaler); !ok {
		t.Fatalf("%T does not implement encoding.TextUnmarshaler", v)
	}
}

func mustBigInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid big.Int string: " + s)
	}
	return v
}
