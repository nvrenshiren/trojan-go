package tunnel

import (
	"context"
	"io"
	"net"

	"github.com/p4gefau1t/trojan-go/common"
)

// Conn 是隧道中的 TCP 连接
type Conn interface {
	net.Conn
	Metadata() *Metadata
}

// PacketConn 是隧道中的 UDP 数据包流
type PacketConn interface {
	net.PacketConn
	WriteWithMetadata([]byte, *Metadata) (int, error)
	ReadWithMetadata([]byte) (int, *Metadata, error)
}

// ConnDialer 从隧道创建 TCP 连接
type ConnDialer interface {
	DialConn(*Address, Tunnel) (Conn, error)
}

// PacketDialer 从隧道创建 UDP 数据包流
type PacketDialer interface {
	DialPacket(Tunnel) (PacketConn, error)
}

// ConnListener 接受 TCP 连接
type ConnListener interface {
	AcceptConn(Tunnel) (Conn, error)
}

// PacketListener 接受 UDP 数据包流
// 我们没有任何基于数据包流的隧道，所以 AcceptPacket 总是会接收到一个真正的 PacketConn
type PacketListener interface {
	AcceptPacket(Tunnel) (PacketConn, error)
}

// Dialer 可以使用隧道拨打到原始服务器
type Dialer interface {
	ConnDialer
	PacketDialer
}

// Listener 可以从隧道接受 TCP 和 UDP 流
type Listener interface {
	ConnListener
	PacketListener
}

// Client 是基于流连接隧道的隧道客户端
type Client interface {
	Dialer
	io.Closer
}

// Server 是基于流连接隧道的隧道服务器
type Server interface {
	Listener
	io.Closer
}

// Tunnel 描述了一个隧道，允许从一个隧道创建另一个隧道
// 我们假设下层隧道精确地知道上层隧道如何工作，并且下层隧道对上层隧道是透明的
type Tunnel interface {
	Name() string
	NewClient(context.Context, Client) (Client, error)
	NewServer(context.Context, Server) (Server, error)
}

var tunnels = make(map[string]Tunnel)

// RegisterTunnel 通过隧道名称注册一个隧道
func RegisterTunnel(name string, tunnel Tunnel) {
	tunnels[name] = tunnel
}

func GetTunnel(name string) (Tunnel, error) {
	if t, ok := tunnels[name]; ok {
		return t, nil
	}
	return nil, common.NewError("未知的隧道名称 " + name)
}
