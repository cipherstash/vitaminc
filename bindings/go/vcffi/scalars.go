package vcffi

import (
	"encoding/binary"
	"time"

	"github.com/cipherstash/vitaminc/bindings/go/vcvalue"
)

func (e Encoder) scalar(tag byte, payload []byte) {
	if e.st.err != nil {
		return
	}
	e.push(tag)
	e.push(payload...)
	e.complete()
}

func (e Encoder) Int8(v int8)               { e.scalar(tagInt8, []byte{byte(v)}) }
func (e Encoder) UInt8(v uint8)             { e.scalar(tagUint8, []byte{v}) }
func (e Encoder) Int16(v int16)             { e.scalar(tagInt16, binary.LittleEndian.AppendUint16(nil, uint16(v))) }
func (e Encoder) UInt16(v uint16)           { e.scalar(tagUint16, binary.LittleEndian.AppendUint16(nil, v)) }
func (e Encoder) Int128(v vcvalue.Int128)   { e.scalar(tagInt128, v[:]) }
func (e Encoder) UInt128(v vcvalue.Uint128) { e.scalar(tagUint128, v[:]) }

func (e Encoder) Date(v vcvalue.Date) {
	if e.st.err != nil {
		return
	}
	days, err := v.DaysFromCE()
	if err != nil {
		e.st.fail(err)
		return
	}
	e.scalar(tagDate, binary.LittleEndian.AppendUint32(nil, uint32(days)))
}

// Timestamp keeps the instant and nanoseconds, discarding location and monotonic metadata.
func (e Encoder) Timestamp(v time.Time) {
	e.TimestampParts(vcvalue.Timestamp{Seconds: v.Unix(), Nanoseconds: uint32(v.Nanosecond())})
}
func (e Encoder) TimestampParts(v vcvalue.Timestamp) {
	if e.st.err != nil {
		return
	}
	if err := v.Validate(); err != nil {
		e.st.fail(err)
		return
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(v.Seconds))
	b = binary.LittleEndian.AppendUint32(b, v.Nanoseconds)
	e.scalar(tagTimestamp, b)
}

func (e Encoder) Decimal(v vcvalue.Decimal) {
	if e.st.err != nil {
		return
	}
	if err := v.Validate(); err != nil {
		e.st.fail(err)
		return
	}
	flags := uint32(v.Scale) << 16
	if v.Negative {
		flags |= 0x80000000
	}
	b := binary.LittleEndian.AppendUint32(nil, flags)
	b = append(b, v.Coefficient[:]...)
	e.scalar(tagDecimal, b)
}

func decodeScalar(r *reader, tag byte) (any, error) {
	widths := map[byte]int{tagInt8: 1, tagUint8: 1, tagInt16: 2, tagUint16: 2, tagDate: 4, tagTimestamp: 12, tagInt128: 16, tagUint128: 16, tagDecimal: 16}
	width, ok := widths[tag]
	if !ok {
		return nil, ErrMalformed
	}
	b, err := r.take(width)
	if err != nil {
		return nil, err
	}
	switch tag {
	case tagInt8:
		return int8(b[0]), nil
	case tagUint8:
		return b[0], nil
	case tagInt16:
		return int16(binary.LittleEndian.Uint16(b)), nil
	case tagUint16:
		return binary.LittleEndian.Uint16(b), nil
	case tagInt128:
		return vcvalue.Int128(b), nil
	case tagUint128:
		return vcvalue.Uint128(b), nil
	case tagDate:
		d, err := vcvalue.DateFromDaysCE(int32(binary.LittleEndian.Uint32(b)))
		if err != nil {
			return nil, ErrMalformed
		}
		return d, nil
	case tagTimestamp:
		t := vcvalue.Timestamp{Seconds: int64(binary.LittleEndian.Uint64(b)), Nanoseconds: binary.LittleEndian.Uint32(b[8:])}
		if t.Validate() != nil {
			return nil, ErrMalformed
		}
		if t.Nanoseconds >= 1000000000 {
			return t, nil
		}
		return time.Unix(t.Seconds, int64(t.Nanoseconds)).UTC(), nil
	case tagDecimal:
		flags := binary.LittleEndian.Uint32(b)
		if flags&0x7f00ffff != 0 {
			return nil, ErrMalformed
		}
		d := vcvalue.Decimal{Scale: uint8(flags >> 16), Negative: flags>>31 != 0}
		copy(d.Coefficient[:], b[4:])
		if d.Validate() != nil {
			return nil, ErrMalformed
		}
		return d, nil
	default:
		return nil, ErrMalformed
	}
}
