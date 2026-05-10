package simplesocks

import (
	"context"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

const (
	Connect   tunnel.Command = 1
	Associate tunnel.Command = 3
)

type Client struct {
	underlay tunnel.Client
}

func (c *Client) DialConn(addr *tunnel.Address, t tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := c.underlay.DialConn(nil, &Tunnel{})
	if err != nil {
		return nil, common.NewError("simplesocks 无法使用底层隧道拨号").Base(err)
	}
	return &Conn{
		Conn:       conn,
		isOutbound: true,
		metadata: &tunnel.Metadata{
			Command: Connect,
			Address: addr,
		},
	}, nil
}

func (c *Client) DialPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	conn, err := c.underlay.DialConn(nil, &Tunnel{})
	if err != nil {
		return nil, common.NewError("simplesocks 无法使用底层隧道拨号").Base(err)
	}
	metadata := &tunnel.Metadata{
		Command: Associate,
		Address: &tunnel.Address{
			DomainName:  "UDP_CONN",
			AddressType: tunnel.DomainName,
		},
	}
	if err := metadata.WriteTo(conn); err != nil {
		return nil, common.NewError("simplesocks 写入 UDP associate 失败").Base(err)
	}
	return &PacketConn{
		PacketConn: trojan.PacketConn{
			Conn: conn,
		},
	}, nil
}

func (c *Client) Close() error {
	return c.underlay.Close()
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	log.Debug("已创建 simplesocks 客户端")
	return &Client{
		underlay: underlay,
	}, nil
}
