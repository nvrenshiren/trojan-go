package transport

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// Server 是传输层的服务器
type Server struct {
	tcpListener net.Listener
	cmd         *exec.Cmd
	connChan    chan tunnel.Conn
	wsChan      chan tunnel.Conn
	httpLock    sync.RWMutex
	nextHTTP    bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		s.cmd.Process.Kill()
	}
	return s.tcpListener.Close()
}

func (s *Server) acceptLoop() {
	for {
		tcpConn, err := s.tcpListener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Error(common.NewError("传输层接受错误").Base(err))
				time.Sleep(time.Millisecond * 100)
			}
			return
		}

		go func(tcpConn net.Conn) {
			log.Info("来自", tcpConn.RemoteAddr(), "的 TCP 连接")
			s.httpLock.RLock()
			if s.nextHTTP { // 启用明文模式
				s.httpLock.RUnlock()
				// 我们使用真正的 HTTP 头解析器来模拟一个真正的 HTTP 服务器
				rewindConn := common.NewRewindConn(tcpConn)
				rewindConn.SetBufferSize(512)
				defer rewindConn.StopBuffering()

				r := bufio.NewReader(rewindConn)
				httpReq, err := http.ReadRequest(r)
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				if err != nil {
					// 这不是 HTTP 请求，将其传递给 trojan 协议层进行进一步检查
					s.connChan <- &Conn{
						Conn: rewindConn,
					}
				} else {
					// 这是一个 HTTP 请求，将其传递给 WebSocket 协议层
					log.Debug("明文 HTTP 请求: ", httpReq)
					s.wsChan <- &Conn{
						Conn: rewindConn,
					}
				}
			} else {
				s.httpLock.RUnlock()
				s.connChan <- &Conn{
					Conn: tcpConn,
				}
			}
		}(tcpConn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	// TODO 修复导入循环
	if overlay != nil && (overlay.Name() == "WEBSOCKET" || overlay.Name() == "HTTP") {
		s.httpLock.Lock()
		s.nextHTTP = true
		s.httpLock.Unlock()
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("传输层服务器已关闭")
		}
	}
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("传输层服务器已关闭")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("不支持")
}

// NewServer 创建传输层服务器
func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	listenAddress := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)

	var cmd *exec.Cmd
	if cfg.TransportPlugin.Enabled {
		log.Warn("传输层服务器将使用插件并以明文模式工作")
		switch cfg.TransportPlugin.Type {
		case "shadowsocks":
			trojanHost := "127.0.0.1"
			trojanPort := common.PickPort("tcp", trojanHost)
			cfg.TransportPlugin.Env = append(
				cfg.TransportPlugin.Env,
				"SS_REMOTE_HOST="+cfg.LocalHost,
				"SS_REMOTE_PORT="+strconv.FormatInt(int64(cfg.LocalPort), 10),
				"SS_LOCAL_HOST="+trojanHost,
				"SS_LOCAL_PORT="+strconv.FormatInt(int64(trojanPort), 10),
				"SS_PLUGIN_OPTIONS="+cfg.TransportPlugin.Option,
			)

			cfg.LocalHost = trojanHost
			cfg.LocalPort = trojanPort
			listenAddress = tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)
			log.Debug("新的监听地址", listenAddress)
			log.Debug("插件环境变量", cfg.TransportPlugin.Env)

			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "other":
			cmd = exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
			cmd.Env = append(cmd.Env, cfg.TransportPlugin.Env...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stdout
			cmd.Start()
		case "plaintext":
			// 不做任何事
		default:
			return nil, common.NewError("无效的插件类型: " + cfg.TransportPlugin.Type)
		}
	}
	tcpListener, err := net.Listen("tcp", listenAddress.String())
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		tcpListener: tcpListener,
		cmd:         cmd,
		ctx:         ctx,
		cancel:      cancel,
		connChan:    make(chan tunnel.Conn, 32),
		wsChan:      make(chan tunnel.Conn, 32),
	}
	go server.acceptLoop()
	return server, nil
}
