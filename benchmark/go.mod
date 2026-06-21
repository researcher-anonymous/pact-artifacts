module pact-benchmark

go 1.23.3

require (
	anonymous-artifact/schoco v1.2.0
	flow-poc/pact v0.0.0
	flow-poc/sd v0.0.0
	github.com/golang-jwt/jwt/v5 v5.3.0
)

require filippo.io/edwards25519 v1.1.0 // indirect

replace flow-poc/sd => ../sd

replace flow-poc/pact => ../pact

replace anonymous-artifact/schoco => ../schoco
