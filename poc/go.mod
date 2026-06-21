module flow-poc

go 1.24.4

toolchain go1.24.11

require (
	anonymous-artifact/schoco v1.2.0
	flow-poc/pact v0.0.0
	flow-poc/sd v0.0.0
	github.com/a2aproject/a2a-go v0.3.3
	github.com/modelcontextprotocol/go-sdk v1.2.0
)

replace flow-poc/sd => ../sd

replace flow-poc/pact => ../pact

replace anonymous-artifact/schoco => ../schoco

require (
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/google/jsonschema-go v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/oauth2 v0.32.0 // indirect
	golang.org/x/sync v0.18.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.31.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251029180050-ab9386a59fda // indirect
	google.golang.org/grpc v1.78.0 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
