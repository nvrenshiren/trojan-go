package websocket

import (
	"context"
	"net"

	"golang.org/x/net/websocket"

	"github.com/p4gefau1t/trojan-go/tunnel"
)

type OutboundConn struct {
	*websocket.Conn
	tcpConn net.Conn
}

func (c *OutboundConn) Metadata() *tunnel.Metadata {
	return nil
}

func (c *OutboundConn) RemoteAddr() net.Addr {
	// 重写 websocket.Conn 的 RemoteAddr，否则它会从 "Origin" 返回一些 URL
	return c.tcpConn.RemoteAddr()
}

type InboundConn struct {
	OutboundConn
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *InboundConn) Close() error {
	c.cancel()
	return c.Conn.Close()
}
