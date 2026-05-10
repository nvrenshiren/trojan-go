package dokodemo

import (
	"context"
	"net"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

const MaxPacketSize = 1024 * 8

type Conn struct {
	net.Conn
	src            *tunnel.Address
	targetMetadata *tunnel.Metadata
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.targetMetadata
}

// PacketConn 从数据包调度器接收数据包信息
type PacketConn struct {
	net.PacketConn
	metadata *tunnel.Metadata
	input    chan []byte
	output   chan []byte
	src      net.Addr
	ctx      context.Context
	cancel   context.CancelFunc
}

func (c *PacketConn) Close() error {
	c.cancel()
	// 不要关闭底层 UDP 套接字
	return nil
}

func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return c.ReadWithMetadata(p)
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	address, err := tunnel.NewAddressFromAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	return c.WriteWithMetadata(p, &tunnel.Metadata{
		Address: address,
	})
}

func (c *PacketConn) ReadWithMetadata(p []byte) (int, *tunnel.Metadata, error) {
	select {
	case payload := <-c.input:
		n := copy(p, payload)
		return n, c.metadata, nil
	case <-c.ctx.Done():
		return 0, nil, common.NewError("dokodemo 数据包连接已关闭")
	}
}

func (c *PacketConn) WriteWithMetadata(p []byte, m *tunnel.Metadata) (int, error) {
	select {
	case c.output <- p:
		return len(p), nil
	case <-c.ctx.Done():
		return 0, common.NewError("dokodemo 数据包连接写入失败")
	}
}
