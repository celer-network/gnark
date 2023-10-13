module github.com/consensys/gnark

go 1.19

require (
	github.com/bits-and-blooms/bitset v1.5.0
	github.com/blang/semver/v4 v4.0.0
	github.com/consensys/bavard v0.1.13
	github.com/consensys/gnark-crypto v0.12.1
	github.com/ethereum/go-ethereum v1.13.2
	github.com/fxamacker/cbor/v2 v2.5.0
	github.com/google/go-cmp v0.5.9
	github.com/google/pprof v0.0.0-20230309165930-d61513b1440d
	github.com/ingonyama-zk/icicle v0.0.0-20230831061944-5667f32bfedd
	github.com/leanovate/gopter v0.2.9
	github.com/rs/zerolog v1.29.0
	github.com/stretchr/testify v1.8.3
	golang.org/x/crypto v0.12.0
	golang.org/x/exp v0.0.0-20230810033253-352e893a4cad
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/holiman/uint256 v1.2.3 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mmcloughlin/addchain v0.4.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/sys v0.11.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	rsc.io/tmplfunc v0.0.3 // indirect
)

replace github.com/consensys/gnark-crypto => github.com/celer-network/gnark-crypto v0.0.0-20230423085214-c00cabca6125

replace github.com/ingonyama-zk/icicle => github.com/ImmanuelSegol/icicle v0.0.0-20231010072137-0f48ec69cadb

//replace github.com/consensys/gnark-crypto => github.com/bytetang/gnark-crypto v0.0.0-20230530142037-050894b6b603
