module qortal.org/qortal-masque-relay

go 1.26.0

replace github.com/quic-go/quic-go => ./third_party/quic-go

replace github.com/quic-go/masque-go => ./third_party/masque-go

require (
	github.com/cloudflare/circl v1.6.5
	github.com/huin/goupnp v1.3.0
	github.com/quic-go/masque-go v0.5.0
	github.com/quic-go/quic-go v0.62.0
	github.com/yosida95/uritemplate/v3 v3.0.2
	go.etcd.io/bbolt v1.4.3
	golang.org/x/crypto v0.54.0
)

require (
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
