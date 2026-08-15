package vcencrypt

// Test-only bridges: the transport codec is deliberately unexported (it is
// an FFI detail, not a storage format), but the external test package needs
// raw decode access for the cross-language fixture.
var (
	UnmarshalForTest           = unmarshal
	UnmarshalCipherTextForTest = unmarshalCipherText
)
