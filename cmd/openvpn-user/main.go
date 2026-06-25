// Command openvpn-user is a thin standalone entrypoint around
// ovpn-admin/internal/ovpnuser. It is built into the OpenVPN server image so
// the auth-user-pass-verify path has the user DB CLI without downloading a
// third-party prebuilt binary. The ovpn-admin image reuses the same logic via
// an argv[0] symlink instead of this binary.
package main

import (
	"os"

	"ovpn-admin/internal/ovpnuser"
)

func main() {
	os.Exit(ovpnuser.RunCLI(os.Args[1:]))
}
