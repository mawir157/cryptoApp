module github.com/mawir157/cryptoApp

go 1.21

toolchain go1.21.5

require (
	github.com/gotk3/gotk3 v0.6.2
	github.com/mawir157/jmtcrypto v0.2.0
)

replace github.com/mawir157/jmtcrypto v0.2.0 => ../jmtcrypto
