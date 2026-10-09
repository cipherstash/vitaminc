package vcvalue

import (
	"errors"
	"math/big"
	"strings"
	"time"
)

var (
	ErrIntegerRange     = errors.New("vcvalue: integer is outside its 128-bit range")
	ErrInvalidDate      = errors.New("vcvalue: invalid date")
	ErrInvalidTimestamp = errors.New("vcvalue: invalid timestamp")
	ErrInvalidDecimal   = errors.New("vcvalue: invalid or out-of-range decimal")
	ErrNonFiniteDecimal = errors.New("vcvalue: decimal must be finite")
)

// Int128 is a signed two's-complement integer in little-endian byte order.
type Int128 [16]byte

// Uint128 is an unsigned integer in little-endian byte order.
type Uint128 [16]byte

func littleInteger(value *big.Int) [16]byte {
	var out [16]byte
	bytes := value.Bytes()
	for i, b := range bytes {
		out[len(bytes)-1-i] = b
	}
	return out
}

func ParseInt128(s string) (Int128, error) {
	value, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return Int128{}, ErrIntegerRange
	}
	limit := new(big.Int).Lsh(big.NewInt(1), 127)
	if value.Cmp(new(big.Int).Neg(new(big.Int).Set(limit))) < 0 || value.Cmp(limit) >= 0 {
		return Int128{}, ErrIntegerRange
	}
	if value.Sign() < 0 {
		value.Add(value, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return Int128(littleInteger(value)), nil
}

func ParseUint128(s string) (Uint128, error) {
	value, ok := new(big.Int).SetString(s, 10)
	if !ok || value.Sign() < 0 || value.BitLen() > 128 {
		return Uint128{}, ErrIntegerRange
	}
	return Uint128(littleInteger(value)), nil
}

func bigInteger(value [16]byte) *big.Int {
	var be [16]byte
	for i, b := range value {
		be[15-i] = b
	}
	return new(big.Int).SetBytes(be[:])
}
func (v Uint128) String() string { return bigInteger([16]byte(v)).String() }
func (v Int128) String() string {
	value := bigInteger([16]byte(v))
	if v[15]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), 128))
	}
	return value.String()
}

// Date is a proleptic Gregorian calendar date, without time or timezone.
// Its range matches chrono::NaiveDate, including year zero and BCE dates.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

func (d Date) Validate() error {
	if d.Year < -262143 || d.Year > 262142 || d.Month < 1 || d.Month > 12 || d.Day < 1 || d.Day > 31 {
		return ErrInvalidDate
	}
	t := time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
	if t.Year() != d.Year || t.Month() != d.Month || t.Day() != d.Day {
		return ErrInvalidDate
	}
	return nil
}

// DaysFromCE returns the frozen wire day count (0001-01-01 is day 1).
func (d Date) DaysFromCE() (int32, error) {
	if err := d.Validate(); err != nil {
		return 0, err
	}
	return int32(time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC).Unix()/86400 + 719163), nil
}

func DateFromDaysCE(days int32) (Date, error) {
	t := time.Unix((int64(days)-719163)*86400, 0).UTC()
	d := Date{Year: t.Year(), Month: t.Month(), Day: t.Day()}
	return d, d.Validate()
}

// Timestamp preserves chrono's leap-second representation, which time.Time
// cannot represent. Ordinary timestamps decode to time.Time; leap seconds
// decode to this type. Both encode with the same Timestamp tag.
type Timestamp struct {
	Seconds     int64
	Nanoseconds uint32
}

func (t Timestamp) Validate() error {
	min := time.Date(-262143, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	max := time.Date(262142, 12, 31, 23, 59, 59, 0, time.UTC).Unix()
	if t.Seconds < min || t.Seconds > max || t.Nanoseconds >= 2000000000 {
		return ErrInvalidTimestamp
	}
	second := (t.Seconds%60 + 60) % 60
	if t.Nanoseconds >= 1000000000 && second != 59 {
		return ErrInvalidTimestamp
	}
	return nil
}

// Decimal is a finite base-10 value: sign * Coefficient * 10^-Scale.
// Coefficient is an unsigned 96-bit little-endian integer. Scale is retained,
// including trailing zeroes, and must be at most 28 (rust_decimal's range).
type Decimal struct {
	Coefficient [12]byte
	Scale       uint8
	Negative    bool
}

func (d Decimal) Validate() error {
	if d.Scale > 28 {
		return ErrInvalidDecimal
	}
	return nil
}

// ParseDecimal accepts exact fixed-point decimal text without rounding.
// NaN and infinities have their own error so callers can reject them by type.
func ParseDecimal(s string) (Decimal, error) {
	switch strings.ToLower(s) {
	case "nan", "+nan", "-nan", "inf", "+inf", "-inf", "infinity", "+infinity", "-infinity":
		return Decimal{}, ErrNonFiniteDecimal
	}
	var d Decimal
	if strings.HasPrefix(s, "-") {
		d.Negative = true
		s = s[1:]
	} else if strings.HasPrefix(s, "+") {
		s = s[1:]
	}
	parts := strings.Split(s, ".")
	if len(parts) > 2 || len(parts[0]) == 0 {
		return Decimal{}, ErrInvalidDecimal
	}
	if len(parts) == 2 {
		if len(parts[1]) == 0 || len(parts[1]) > 28 {
			return Decimal{}, ErrInvalidDecimal
		}
		d.Scale = uint8(len(parts[1]))
	}
	digits := strings.Join(parts, "")
	for _, c := range digits {
		if c < '0' || c > '9' {
			return Decimal{}, ErrInvalidDecimal
		}
	}
	if len(strings.TrimLeft(digits, "0")) > 29 {
		return Decimal{}, ErrInvalidDecimal
	}
	coefficient, ok := new(big.Int).SetString(digits, 10)
	if !ok || coefficient.BitLen() > 96 {
		return Decimal{}, ErrInvalidDecimal
	}
	raw := littleInteger(coefficient)
	copy(d.Coefficient[:], raw[:12])
	return d, nil
}

func (d Decimal) String() string {
	var raw [16]byte
	copy(raw[:12], d.Coefficient[:])
	digits := bigInteger(raw).String()
	scale := int(d.Scale)
	if scale > 0 {
		if len(digits) <= scale {
			digits = strings.Repeat("0", scale+1-len(digits)) + digits
		}
		digits = digits[:len(digits)-scale] + "." + digits[len(digits)-scale:]
	}
	if d.Negative {
		digits = "-" + digits
	}
	return digits
}
