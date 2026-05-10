package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/p4gefau1t/trojan-go/api"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/statistic/memory"
	"github.com/p4gefau1t/trojan-go/statistic/mysql"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/mux"
)

// InboundConn 是 trojan 入站连接
type InboundConn struct {
	// 警告：不要更改这些字段的顺序。
	// 使用 `sync/atomic` 包函数的 64 位字段
	// 必须在 32 位系统上 64 位对齐。
	// 参考：https://github.com/golang/go/issues/599
	// 解决方案：https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth     statistic.Authenticator
	user     statistic.User
	hash     string
	metadata *tunnel.Metadata
	ip       string
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddTraffic(n, 0)
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddTraffic(0, n)
	return n, err
}

func (c *InboundConn) Close() error {
	log.Info("用户", c.hash, "从", c.Conn.RemoteAddr(), "隧道连接到", c.metadata.Address, "已关闭",
		"发送:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "接收:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return common.NewError("读取哈希失败").Base(err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]))
	if !valid {
		return common.NewError("无效的哈希:" + string(userHash[:]))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("解析主机失败:" + c.Conn.RemoteAddr().String()).Base(err)
	}

	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return common.NewError("IP 限制已达到")
	}

	crlf := [2]byte{}
	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}

	c.metadata = &tunnel.Metadata{}
	if err := c.metadata.ReadFrom(c.Conn); err != nil {
		return err
	}

	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}
	return nil
}

// Server 是 trojan 隧道服务器
type Server struct {
	auth       statistic.Authenticator
	redir      *redirector.Redirector
	redirAddr  *tunnel.Address
	underlay   tunnel.Server
	connChan   chan tunnel.Conn
	muxChan    chan tunnel.Conn
	packetChan chan tunnel.PacketConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // 关闭中
			log.Error(common.NewError("trojan 无法接受连接").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn: rewindConn,
				auth: s.auth,
			}

			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("来自 " + rewindConn.RemoteAddr().String() + " 的无效 trojan 头连接").Base(err))
				s.redir.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" {
					s.muxChan <- inboundConn
					log.Debug("mux(r) 连接")
				} else {
					s.connChan <- inboundConn
					log.Debug("普通 trojan 连接")
				}

			case Associate:
				s.packetChan <- &PacketConn{
					Conn: inboundConn,
				}
				log.Debug("trojan UDP 连接")
			case Mux:
				s.muxChan <- inboundConn
				log.Debug("mux 连接")
			default:
				log.Error(common.NewError(fmt.Sprintf("未知的 trojan 命令 %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(nextTunnel tunnel.Tunnel) (tunnel.Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel:
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan 客户端已关闭")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan 客户端已关闭")
		}
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan 客户端已关闭")
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)

	// TODO 替换这段脏代码
	var auth statistic.Authenticator
	var err error
	if cfg.MySQL.Enabled {
		log.Debug("已启用 MySQL")
		auth, err = statistic.NewAuthenticator(ctx, mysql.Name)
	} else {
		log.Debug("通过配置文件认证")
		auth, err = statistic.NewAuthenticator(ctx, memory.Name)
	}
	if err != nil {
		cancel()
		return nil, common.NewError("trojan 无法创建认证器")
	}

	if cfg.API.Enabled {
		go api.RunService(ctx, Name+"_SERVER", auth)
	}

	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	s := &Server{
		underlay:   underlay,
		auth:       auth,
		redirAddr:  redirAddr,
		connChan:   make(chan tunnel.Conn, 32),
		muxChan:    make(chan tunnel.Conn, 32),
		packetChan: make(chan tunnel.PacketConn, 32),
		ctx:        ctx,
		cancel:     cancel,
		redir:      redirector.NewRedirector(ctx),
	}

	if !cfg.DisableHTTPCheck {
		redirConn, err := net.Dial("tcp", redirAddr.String())
		if err != nil {
			cancel()
			return nil, common.NewError("无效的重定向地址。请检查您的 HTTP 服务器: " + redirAddr.String()).Base(err)
		}
		redirConn.Close()
	}

	go s.acceptLoop()
	log.Debug("已创建 trojan 服务器")
	return s, nil
}
