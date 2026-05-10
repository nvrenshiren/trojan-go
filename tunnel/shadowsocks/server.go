package shadowsocks

import (
	"context"
	"net"

	"github.com/shadowsocks/go-shadowsocks2/core"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

type Server struct {
	core.Cipher
	*redirector.Redirector
	underlay  tunnel.Server
	redirAddr net.Addr
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := s.underlay.AcceptConn(&Tunnel{})
	if err != nil {
		return nil, common.NewError("shadowsocks 无法接受来自底层隧道的连接").Base(err)
	}
	rewindConn := common.NewRewindConn(conn)
	rewindConn.SetBufferSize(1024)
	defer rewindConn.StopBuffering()

	// 尝试从这个连接读取一些数据
	buf := [1024]byte{}
	testConn := s.Cipher.StreamConn(rewindConn)
	if _, err := testConn.Read(buf[:]); err != nil {
		// 我们正在遭受攻击
		log.Error(common.NewError("shadowsocks 解密失败").Base(err))
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.Redirect(&redirector.Redirection{
			RedirectTo:  s.redirAddr,
			InboundConn: rewindConn,
		})
		return nil, common.NewError("无效的 aead 负载")
	}
	rewindConn.Rewind()
	rewindConn.StopBuffering()

	return &Conn{
		aeadConn: s.Cipher.StreamConn(rewindConn),
		Conn:     conn,
	}, nil
}

func (s *Server) AcceptPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("不支持")
}

func (s *Server) Close() error {
	return s.underlay.Close()
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	cipher, err := core.PickCipher(cfg.Shadowsocks.Method, nil, cfg.Shadowsocks.Password)
	if err != nil {
		return nil, common.NewError("无效的 shadowsocks 加密方式").Base(err)
	}
	if cfg.RemoteHost == "" {
		return nil, common.NewError("无效的 shadowsocks 重定向地址")
	}
	if cfg.RemotePort == 0 {
		return nil, common.NewError("无效的 shadowsocks 重定向端口")
	}
	log.Debug("已创建 shadowsocks 客户端")
	return &Server{
		underlay:   underlay,
		Cipher:     cipher,
		Redirector: redirector.NewRedirector(ctx),
		redirAddr:  tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
	}, nil
}
