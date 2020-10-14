module github.com/corestario/kyber

require (
	github.com/bazelbuild/rules_go v0.24.3 // indirect
	github.com/cloudflare/roughtime v0.0.0-20200911173848-eb42b5b8e068 // indirect
	github.com/d4l3k/messagediff v1.2.1 // indirect
	github.com/dgraph-io/ristretto v0.0.3 // indirect
	github.com/ethereum/go-ethereum v1.9.22 // indirect
	github.com/ferranbt/fastssz v0.0.0-20200826142241-3a913c5a1313 // indirect
	github.com/go-yaml/yaml v2.1.0+incompatible // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/herumi/bls-eth-go-binary v0.0.0-20201008062400-71567a52ad65 // indirect
	github.com/kilic/bls12-381 v0.0.0-20200820230200-6b2c19996391
	github.com/minio/highwayhash v1.0.1 // indirect
	github.com/prometheus/client_golang v1.7.1 // indirect
	github.com/protolambda/zssz v0.1.5 // indirect
	github.com/prysmaticlabs/ethereumapis v0.0.0-20201003171600-a72e5f77d233 // indirect
	github.com/prysmaticlabs/go-bitfield v0.0.0-20200618145306-2ae0807bef65 // indirect
	github.com/prysmaticlabs/go-ssz v0.0.0-20200612203617-6d5c9aa213ae // indirect
	github.com/prysmaticlabs/prysm v1.0.0-alpha.29.0.20201014075528-022b6667e5d0
	github.com/sirupsen/logrus v1.7.0 // indirect
	github.com/stretchr/testify v1.6.1
	go.dedis.ch/fixbuf v1.0.3
	go.dedis.ch/protobuf v1.0.11
	go.opencensus.io v0.22.5 // indirect
	golang.org/x/crypto v0.0.0-20200728195943-123391ffb6de
	golang.org/x/sys v0.0.0-20200824131525-c12d262b63d8
	gopkg.in/d4l3k/messagediff.v1 v1.2.1 // indirect
	k8s.io/api v0.19.2 // indirect
	k8s.io/client-go v11.0.0+incompatible // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/utils v0.0.0-20201005171033-6301aaf42dc7 // indirect
)

go 1.12

//replace gopkg.in/urfave/cli.v2 => github.com/urfave/cli/v2 v2.2.0

replace github.com/ethereum/go-ethereum => github.com/ethereum/go-ethereum v1.9.22
