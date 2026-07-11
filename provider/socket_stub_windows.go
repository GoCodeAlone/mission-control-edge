//go:build windows

package provider

import (
	"context"
	"net"

	"github.com/GoCodeAlone/mission-control-edge/protocol"
)

const unixSocketCapability protocol.CapabilityName = "dev.gocodealone.mission-control/socket.unix"

func ListenUnix(string) (net.Listener, error) {
	return nil, protocol.NotSupported(unixSocketCapability, nil)
}

func DialUnix(context.Context, string) (net.Conn, error) {
	return nil, protocol.NotSupported(unixSocketCapability, nil)
}
