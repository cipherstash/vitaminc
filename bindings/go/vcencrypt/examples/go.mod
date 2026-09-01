// Separate module on purpose: the examples pull in sqlx and a pure-Go
// sqlite driver, which must not become dependencies of the vcencrypt
// binding itself.
module github.com/cipherstash/vitaminc/bindings/go/vcencrypt/examples

go 1.25.0

require (
	github.com/cipherstash/vitaminc/bindings/go/vcencrypt v0.0.0
	github.com/cipherstash/vitaminc/bindings/go/vcvalue v0.0.0
	github.com/jmoiron/sqlx v1.4.0
	modernc.org/sqlite v1.39.0
)

require (
	github.com/cipherstash/vitaminc/bindings/go/vcffi v0.0.0-00010101000000-000000000000 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tetratelabs/wazero v1.12.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/sys v0.44.0 // indirect
	modernc.org/libc v1.66.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/cipherstash/vitaminc/bindings/go/vcencrypt => ../

replace github.com/cipherstash/vitaminc/bindings/go/vcffi => ../../vcffi

replace github.com/cipherstash/vitaminc/bindings/go/vcvalue => ../../vcvalue
