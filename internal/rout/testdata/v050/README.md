`state.json` and `token.txt` were produced by the real Rout v0.5.0 code (tag `v0.5.0`, its own test
scene: VLESS/SS/AnyTLS nodes, a relay, a SOCKS5 exit, AI routing enabled and bound to the first
node, one subscription). All secrets are random values generated for that run. They are used only by
`compat_v050_test.go`, which must keep passing: a newer version has to read, serve and write this
state without changing it.
