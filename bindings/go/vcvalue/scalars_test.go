package vcvalue

import (
	"errors"
	"testing"
	"time"
)

func TestInteger128Boundaries(t *testing.T) {
	for _, text := range []string{"0", "-1", "170141183460469231731687303715884105727", "-170141183460469231731687303715884105728"} {
		v, err := ParseInt128(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	for _, text := range []string{"0", "1", "340282366920938463463374607431768211455"} {
		v, err := ParseUint128(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	for _, text := range []string{"bad", "170141183460469231731687303715884105728", "-170141183460469231731687303715884105729"} {
		if _, err := ParseInt128(text); !errors.Is(err, ErrIntegerRange) {
			t.Fatalf("accepted %s", text)
		}
	}
	for _, text := range []string{"bad", "-1", "340282366920938463463374607431768211456"} {
		if _, err := ParseUint128(text); !errors.Is(err, ErrIntegerRange) {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestDecimalExactness(t *testing.T) {
	for _, text := range []string{"0", "-0.00", "1.50", "-79228162514264337593543950335", "0.0000000000000000000000000001"} {
		v, err := ParseDecimal(text)
		if err != nil || v.String() != text {
			t.Fatalf("%s: %v %s", text, err, v.String())
		}
	}
	for _, text := range []string{"NaN", "+nan", "-NaN", "inf", "+Infinity", "-Infinity"} {
		if _, err := ParseDecimal(text); !errors.Is(err, ErrNonFiniteDecimal) {
			t.Fatalf("%s: %v", text, err)
		}
	}
	for _, text := range []string{"", ".1", "1.", "1.2.3", "1e2", "1_0", " 1", "a", "0.00000000000000000000000000001", "79228162514264337593543950336"} {
		if _, err := ParseDecimal(text); !errors.Is(err, ErrInvalidDecimal) {
			t.Fatalf("accepted %s", text)
		}
	}
}

func TestDatesAndTimestampBounds(t *testing.T) {
	for _, d := range []Date{{1, 1, 1}, {0, 1, 1}, {2024, 2, 29}, {-262143, 1, 1}, {262142, 12, 31}} {
		days, err := d.DaysFromCE()
		if err != nil {
			t.Fatal(err)
		}
		got, err := DateFromDaysCE(days)
		if err != nil || got != d {
			t.Fatalf("%v: %v %v", d, got, err)
		}
	}
	for _, d := range []Date{{2023, 2, 29}, {2024, 0, 1}, {2024, 13, 1}, {2024, 1, 0}, {2024, 1, 32}, {-262144, 1, 1}, {262143, 1, 1}} {
		if d.Validate() == nil {
			t.Fatalf("accepted %v", d)
		}
	}
	for _, ts := range []Timestamp{{0, 0}, {-1, 999999999}, {59, 1123456789}, {-1, 1999999999}} {
		if ts.Validate() != nil {
			t.Fatalf("rejected %v", ts)
		}
	}
	for _, ts := range []Timestamp{{0, 1000000000}, {59, 2000000000}, {time.Date(262143, 1, 1, 0, 0, 0, 0, time.UTC).Unix(), 0}, {1<<63 - 1, 0}} {
		if ts.Validate() == nil {
			t.Fatalf("accepted %v", ts)
		}
	}
}
