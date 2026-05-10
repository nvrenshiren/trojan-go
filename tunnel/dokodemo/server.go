package dokodemo

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

type Server struct {
	tunnel.Server
	tcpListener net.Listener
	udpListener net.PacketConn
	packetChan  chan tunnel.PacketConn
	timeout     time.Duration
	targetAddr  *tunnel.Address
	mappingLock sync.Mutex
	mapping     map[string]*PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) dispatchLoop() {
	fixedMetadata := &tunnel.Metadata{
		Address: s.targetAddr,
	}
	for {
		buf := make([]byte, MaxPacketSize)
		n, addr, err := s.udpListener.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatal(common.NewError("dokodemo 无法从 UDP 套接字读取").Base(err))
			}
			return
		}
		log.Debug("来自", addr, "的 UDP 数据包")
		s.mappingLock.Lock()
		if conn, found := s.mapping[addr.String()]; found {
			conn.input <- buf[:n]
			s.mappingLock.Unlock()
			continue
		}
		ctx, cancel := context.WithCancel(s.ctx)
		conn := &PacketConn{
			input:      make(chan []byte, 16),
			output:     make(chan []byte, 16),
			metadata:   fixedMetadata,
			src:        addr,
			PacketConn: s.udpListener,
			ctx:        ctx,
			cancel:     cancel,
		}
		s.mapping[addr.String()] = conn
		s.mappingLock.Unlock()

		conn.input <- buf[:n]
		s.packetChan <- conn

		go func(conn *PacketConn) {
			for {
				select {
				case payload := <-conn.output:
					// "多个 goroutine 可能同时调用 Conn 上的方法。"
					_, err := s.udpListener.WriteTo(payload, conn.src)
					if err != nil {
						log.Error(common.NewError("dokodemo UDP 写入错误").Base(err))
						return
					}
				case <-s.ctx.Done():
					return
				case <-time.After(s.timeout):
					s.mappingLock.Lock()
					delete(s.mapping, conn.src.String())
					s.mappingLock.Unlock()
					conn.Close()
					log.Debug("正在关闭超时的 packetConn")
					return
				}
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := s.tcpListener.Accept()
	if err != nil {
		log.Fatal(common.NewError("dokodemo 无法接受连接").Base(err))
	}
	return &Conn{
		Conn: conn,
		targetMetadata: &tunnel.Metadata{
			Address: s.targetAddr,
		},
	}, nil
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("dokodemo 服务器已关闭")
	}
}

func (s *Server) Close() error {
	s.cancel()
	s.tcpListener.Close()
	s.udpListener.Close()
	return nil
}

func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	targetAddr := tunnel.NewAddressFromHostPort("tcp", cfg.TargetHost, cfg.TargetPort)
	listenAddr := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)

	tcpListener, err := net.Listen("tcp", listenAddr.String())
	if err != nil {
		return nil, common.NewError("监听 TCP 失败").Base(err)
	}
	udpListener, err := net.ListenPacket("udp", listenAddr.String())
	if err != nil {
		return nil, common.NewError("监听 UDP 失败").Base(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		tcpListener: tcpListener,
		udpListener: udpListener,
		targetAddr:  targetAddr,
		mapping:     make(map[string]*PacketConn),
		packetChan:  make(chan tunnel.PacketConn, 32),
		timeout:     time.Second * time.Duration(cfg.UDPTimeout),
		ctx:         ctx,
		cancel:      cancel,
	}
	go server.dispatchLoop()
	return server, nil
}
