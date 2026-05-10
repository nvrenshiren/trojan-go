package simplesocks

import (
	"bytes"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

// Conn 是一个 simplesocks 连接
type Conn struct {
	tunnel.Conn
	metadata      *tunnel.Metadata
	isOutbound    bool
	headerWritten bool
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *Conn) Write(payload []byte) (int, error) {
	if c.isOutbound && !c.headerWritten {
		buf := bytes.NewBuffer(make([]byte, 0, 4096))
		c.metadata.WriteTo(buf)
		buf.Write(payload)
		_, err := c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, common.NewError("写入 simplesocks 头部失败").Base(err)
		}
		c.headerWritten = true
		return len(payload), nil
	}
	return c.Conn.Write(payload)
}

// PacketConn 是一个 simplesocks 数据包连接
// 头部语法与 trojan 相同
type PacketConn struct {
	trojan.PacketConn
}
