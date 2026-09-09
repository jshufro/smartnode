package units

import (
	"bytes"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/shopspring/decimal"
)

func TestUnitJSONRoundTrip(t *testing.T) {
	// Values with more significant digits than float64 can represent exactly.
	preciseEth := "1234567890.123456789012345678"
	preciseGwei := "9876543210.987654321"
	preciseMilli := "111222333444.555666777"
	preciseWei := new(big.Int)
	preciseWei.SetString("123456789012345678901234567890", 10) // > 2^53

	t.Run("Eth", func(t *testing.T) {
		in := &Eth{Decimal: decimal.RequireFromString(preciseEth)}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		assertQuotedJSONString(t, raw, preciseEth)

		var out Eth
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip eth = %s, want %s", out, in)
		}
	})

	t.Run("Gwei", func(t *testing.T) {
		in := &Gwei{Decimal: decimal.RequireFromString(preciseGwei)}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		assertQuotedJSONString(t, raw, preciseGwei)

		var out Gwei
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip gwei = %s, want %s", out, in)
		}
	})

	t.Run("MilliEth", func(t *testing.T) {
		in := &MilliEth{Decimal: decimal.RequireFromString(preciseMilli)}
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		assertQuotedJSONString(t, raw, preciseMilli)

		var out MilliEth
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if !in.Equal(out.Decimal) {
			t.Fatalf("round-trip milliEth = %s, want %s", out, in)
		}
	})

	t.Run("Wei", func(t *testing.T) {
		in := newWei(preciseWei)
		raw, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if string(raw) != preciseWei.String() {
			t.Fatalf("marshal wei = %s, want %s", raw, preciseWei)
		}

		var out Wei
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if in.Cmp(&out.Int) != 0 {
			t.Fatalf("round-trip wei = %s, want %s", &out.Int, in)
		}

		// Value marshal must also preserve digits (not encode as {}).
		rawValue, err := json.Marshal(*in)
		if err != nil {
			t.Fatalf("marshal wei value: %v", err)
		}
		if string(rawValue) != preciseWei.String() {
			t.Fatalf("marshal wei value = %s, want %s", rawValue, preciseWei)
		}
	})
}

func TestUnitJSONStructFields(t *testing.T) {
	type payload struct {
		Wei      Wei      `json:"wei"`
		Eth      Eth      `json:"eth"`
		Gwei     Gwei     `json:"gwei"`
		MilliEth MilliEth `json:"milliEth"`
	}

	in := payload{
		Wei:      *newWei(pow10(18)),
		Eth:      Eth{Decimal: decimal.RequireFromString("1.000000000000000001")},
		Gwei:     Gwei{Decimal: decimal.RequireFromString("2000000000.000000001")},
		MilliEth: MilliEth{Decimal: decimal.RequireFromString("3000.000000000000001")},
	}

	// Marshal by value to ensure pointer-receiver-only methods are not required.
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var out payload
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if in.Wei.Cmp(&out.Wei.Int) != 0 {
		t.Errorf("wei = %s, want %s", &out.Wei.Int, &in.Wei.Int)
	}
	if !in.Eth.Equal(out.Eth.Decimal) {
		t.Errorf("eth = %s, want %s", out.Eth, in.Eth)
	}
	if !in.Gwei.Equal(out.Gwei.Decimal) {
		t.Errorf("gwei = %s, want %s", out.Gwei, in.Gwei)
	}
	if !in.MilliEth.Equal(out.MilliEth.Decimal) {
		t.Errorf("milliEth = %s, want %s", out.MilliEth, in.MilliEth)
	}
}

func TestUnitJSONDoesNotUseFloat(t *testing.T) {
	// float64 cannot represent this eth amount exactly; JSON must not go through float.
	const amount = "0.123456789012345678"
	in := &Eth{Decimal: decimal.RequireFromString(amount)}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	assertQuotedJSONString(t, raw, amount)

	var asFloat float64
	if err := json.Unmarshal([]byte(amount), &asFloat); err != nil {
		t.Fatalf("unmarshal float: %v", err)
	}
	if decimal.NewFromFloat(asFloat).Equal(in.Decimal) {
		t.Fatal("expected float64 path to lose precision; test value is not discriminating enough")
	}

	var out Eth
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal eth: %v", err)
	}
	if !out.Equal(in.Decimal) {
		t.Fatalf("eth json path lost precision: got %s, want %s", out, in)
	}
}

func TestWeiJSONPreservesBeyondFloatMantissa(t *testing.T) {
	// 2^53 + 1 cannot be represented exactly as float64.
	in := newWei(new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 53), big.NewInt(1)))

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != in.String() {
		t.Fatalf("marshal = %s, want %s", raw, in)
	}

	var asFloat float64
	if err := json.Unmarshal(raw, &asFloat); err != nil {
		t.Fatalf("unmarshal float: %v", err)
	}
	floatWei := decimal.NewFromFloat(asFloat).BigInt()
	if floatWei.Cmp(&in.Int) == 0 {
		t.Fatal("expected float64 path to lose precision for 2^53+1")
	}

	var out Wei
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal wei: %v", err)
	}
	if in.Cmp(&out.Int) != 0 {
		t.Fatalf("wei json path lost precision: got %s, want %s", &out.Int, in)
	}
}

func assertQuotedJSONString(t *testing.T, raw []byte, want string) {
	t.Helper()
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		t.Fatalf("expected quoted JSON string, got %s: %v", raw, err)
	}
	if s != want {
		t.Fatalf("json string = %q, want %q (raw %s)", s, want, raw)
	}
	if !bytes.HasPrefix(raw, []byte(`"`)) || !bytes.HasSuffix(raw, []byte(`"`)) {
		t.Fatalf("expected quoted encoding, got %s", raw)
	}
}
