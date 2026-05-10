package websocket

import (
	"bufio"
	"context"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// 伪造的响应写入器
// Websocket ServeHTTP 方法使用 Hijack 方法来获取 ReadWriter
type fakeHTTPResponseWriter struct {
	http.Hijacker
	http.ResponseWriter

	ReadWriter *bufio.ReadWriter
	Conn       net.Conn
}

func (w *fakeHTTPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Conn, w.ReadWriter, nil
}

type Server struct {
	underlay  tunnel.Server
	hostname  string
	path      string
	enabled   bool
	redirAddr net.Addr
	redir     *redirector.Redirector
	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := s.underlay.AcceptConn(&Tunnel{})
	if err != nil {
		return nil, common.NewError("websocket 无法接受来自底层服务器的连接")
	}
	if !s.enabled {
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: conn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("websocket 已禁用。正在重定向来自 " + conn.RemoteAddr().String() + " 的 HTTP 请求")
	}
	rewindConn := common.NewRewindConn(conn)
	rewindConn.SetBufferSize(512)
	defer rewindConn.StopBuffering()
	rw := bufio.NewReadWriter(bufio.NewReader(rewindConn), bufio.NewWriter(rewindConn))
	req, err := http.ReadRequest(rw.Reader)
	if err != nil {
		log.Debug("无效的 HTTP 请求")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("不是有效的 HTTP 请求: " + conn.RemoteAddr().String()).Base(err)
	}
	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || req.URL.Path != s.path {
		log.Debug("无效的 HTTP WebSocket 握手请求")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("不是有效的 WebSocket 握手请求: " + conn.RemoteAddr().String()).Base(err)
	}

	handshake := make(chan struct{})

	url := "wss://" + s.hostname + s.path
	origin := "https://" + s.hostname
	wsConfig, err := websocket.NewConfig(url, origin)
	if err != nil {
		return nil, common.NewError("创建 WebSocket 配置失败").Base(err)
	}
	var wsConn *websocket.Conn
	ctx, cancel := context.WithCancel(s.ctx)

	wsServer := websocket.Server{
		Config: *wsConfig,
		Handler: func(conn *websocket.Conn) {
			wsConn = conn                              // 握手后存储 websocket
			wsConn.PayloadType = websocket.BinaryFrame // 将其视为二进制 websocket

			log.Debug("已获得 WebSocket 连接")
			handshake <- struct{}{}
			// 此函数不应返回，除非连接结束
			// 否则 websocket 将被 ServeHTTP 方法关闭
			<-ctx.Done()
			log.Debug("WebSocket 已关闭")
		},
		Handshake: func(wsConfig *websocket.Config, httpRequest *http.Request) error {
			log.Debug("WebSocket URL", httpRequest.URL, "来源", httpRequest.Header.Get("Origin"))
			return nil
		},
	}

	respWriter := &fakeHTTPResponseWriter{
		Conn:       conn,
		ReadWriter: rw,
	}
	go wsServer.ServeHTTP(respWriter, req)

	select {
	case <-handshake:
	case <-time.After(s.timeout):
	}

	if wsConn == nil {
		cancel()
		return nil, common.NewError("WebSocket 握手失败")
	}

	return &InboundConn{
		OutboundConn: OutboundConn{
			tcpConn: conn,
			Conn:    wsConn,
		},
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	return nil, common.NewError("不支持")
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg.Websocket.Enabled {
		if !strings.HasPrefix(cfg.Websocket.Path, "/") {
			return nil, common.NewError("WebSocket 路径必须以 \"/\" 开头")
		}
	}
	if cfg.RemoteHost == "" {
		log.Warn("空的 WebSocket 重定向主机名")
		cfg.RemoteHost = cfg.Websocket.Host
	}
	if cfg.RemotePort == 0 {
		log.Warn("空的 WebSocket 重定向端口")
		cfg.RemotePort = 80
	}
	ctx, cancel := context.WithCancel(ctx)
	log.Debug("已创建 WebSocket 服务器")
	return &Server{
		enabled:   cfg.Websocket.Enabled,
		hostname:  cfg.Websocket.Host,
		path:      cfg.Websocket.Path,
		ctx:       ctx,
		cancel:    cancel,
		underlay:  underlay,
		timeout:   time.Second * time.Duration(rand.Intn(10)+5),
		redir:     redirector.NewRedirector(ctx),
		redirAddr: tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
	}, nil
}
