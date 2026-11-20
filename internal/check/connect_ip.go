package check

import (
	"context"
	"net"
	"net/netip"

	"github.com/vincent119/tlscheck/internal/model"
)

// ConnectionInfo 分開保存要求的IP與實際連線觀測；無效PeerAddress表示尚未取得。
type ConnectionInfo struct {
	RequestedIP netip.Addr
	Connected   bool
	PeerAddress netip.AddrPort
}

// CheckWithIP 僅對本次呼叫指定撥號IP，原target仍決定SNI與驗證名稱。
func (c *RemoteChecker) CheckWithIP(ctx context.Context, target model.Target, ip netip.Addr) RemoteResult {
	return c.checkWithIP(ctx, target, &ip)
}

func observedPeer(address net.Addr) netip.AddrPort {
	if address == nil {
		return netip.AddrPort{}
	}
	peer, err := netip.ParseAddrPort(address.String())
	if err != nil || peer.Addr().Zone() != "" || peer.Port() == 0 {
		return netip.AddrPort{}
	}
	return peer
}
