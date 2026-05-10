//go:build linux
// +build linux

package tproxy

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

const MaxPacketSize = 1024 * 8

type Server struct {
	tcpListener net.Listener
	udpListener *net.UDPConn
	packetChan  chan tunnel.PacketConn
	timeout     time.Duration
	mappingLock sync.RWMutex
	mapping     map[string]*PacketConn
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	s.tcpListener.Close()
	return s.udpListener.Close()
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := s.tcpListener.Accept()
	if err != nil {
		select {
		case <-s.ctx.Done():
		default:
			log.Fatal(common.NewError("tproxy 无法接受连接").Base(err))
		}
		return nil, common.NewError("tproxy 无法接受连接")
	}
	dst, err := getOriginalTCPDest(conn.(*net.TCPConn))
	if err != nil {
		return nil, common.NewError("tproxy 无法获取 TCP 套接字的原始地址").Base(err)
	}
	address, err := tunnel.NewAddressFromAddr("tcp", dst.String())
	common.Must(err)
	log.Info("tproxy 连接来自", conn.RemoteAddr().String(), "元数据", dst.String())
	return &Conn{
		metadata: &tunnel.Metadata{
			Address: address,
		},
		Conn: conn,
	}, nil
}

func (s *Server) packetDispatchLoop() {
	type tproxyPacketInfo struct {
		src     *net.UDPAddr
		dst     *net.UDPAddr
		payload []byte
	}
	packetQueue := make(chan *tproxyPacketInfo, 1024)

	go func() {
		for {
			buf := make([]byte, MaxPacketSize)
			n, src, dst, err := ReadFromUDP(s.udpListener, buf)
			if err != nil {
				select {
				case <-s.ctx.Done():
				default:
					log.Fatal(common.NewError("tproxy 无法从 UDP 套接字读取").Base(err))
				}
				s.Close()
				return
			}
			log.Debug("来自", src, "的 UDP 数据包，元数据", dst, "大小", n)
			packetQueue <- &tproxyPacketInfo{
				src:     src,
				dst:     dst,
				payload: buf[:n],
			}
		}
	}()

	for {
		var info *tproxyPacketInfo
		select {
		case info = <-packetQueue:
		case <-s.ctx.Done():
			log.Debug("正在退出")
			return
		}

		s.mappingLock.RLock()
		conn, found := s.mapping[info.src.String()]
		s.mappingLock.RUnlock()

		if !found {
			ctx, cancel := context.WithCancel(s.ctx)
			conn = &PacketConn{
				input:      make(chan *packetInfo, 128),
				output:     make(chan *packetInfo, 128),
				PacketConn: s.udpListener,
				ctx:        ctx,
				cancel:     cancel,
				src:        info.src,
			}

			s.mappingLock.Lock()
			s.mapping[info.src.String()] = conn
			s.mappingLock.Unlock()

			log.Info("来自", info.src.String(), "的新的 tproxy UDP 会话，元数据", info.dst.String())
			s.packetChan <- conn

			go func(conn *PacketConn) {
				defer conn.Close()
				log.Debug("UDP 数据包守护进程 for", conn.src.String())
				for {
					select {
					case info := <-conn.output:
						if info.metadata.AddressType != tunnel.IPv4 &&
							info.metadata.AddressType != tunnel.IPv6 {
							log.Error("tproxy 无效的响应元数据地址", info.metadata)
							continue
						}
						back, err := DialUDP(
							"udp",
							&net.UDPAddr{
								IP:   info.metadata.IP,
								Port: info.metadata.Port,
							},
							conn.src.(*net.UDPAddr),
						)
						if err != nil {
							log.Error(common.NewError("拨打 tproxy UDP 失败").Base(err))
							return
						}
						n, err := back.Write(info.payload)
						if err != nil {
							log.Error(common.NewError("tproxy UDP 写入错误").Base(err))
							return
						}
						log.Debug("接收数据包，发送回", conn.src, "负载", len(info.payload), "发送", n)
						back.Close()
					case <-s.ctx.Done():
						log.Debug("正在退出")
						return
					case <-time.After(s.timeout):
						s.mappingLock.Lock()
						delete(s.mapping, conn.src.String())
						s.mappingLock.Unlock()
						log.Debug("数据包会话 ", conn.src.String(), "超时")
						return
					}
				}
			}(conn)
		}

		newInfo := &packetInfo{
			metadata: &tunnel.Metadata{
				Address: tunnel.NewAddressFromHostPort("udp", info.dst.IP.String(), info.dst.Port),
			},
			payload: info.payload,
		}

		select {
		case conn.input <- newInfo:
			log.Debug("tproxy 数据包发送，元数据", newInfo.metadata, "大小", len(info.payload))
		default:
			// 如果我们收到太多数据包，就直接丢弃它
			log.Warn("tproxy UDP 中继队列已满！")
		}
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		log.Info("tproxy 数据包连接已接受")
		return conn, nil
	case <-s.ctx.Done():
		return nil, io.EOF
	}
}

func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	listenAddr := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)
	ip, err := listenAddr.ResolveIP()
	if err != nil {
		cancel()
		return nil, common.NewError("无效的 tproxy 本地地址").Base(err)
	}
	tcpListener, err := ListenTCP("tcp", &net.TCPAddr{
		IP:   ip,
		Port: cfg.LocalPort,
	})
	if err != nil {
		cancel()
		return nil, common.NewError("tproxy 无法监听 TCP").Base(err)
	}

	udpListener, err := ListenUDP("udp", &net.UDPAddr{
		IP:   ip,
		Port: cfg.LocalPort,
	})
	if err != nil {
		cancel()
		return nil, common.NewError("tproxy 无法监听 UDP").Base(err)
	}

	server := &Server{
		tcpListener: tcpListener,
		udpListener: udpListener,
		ctx:         ctx,
		cancel:      cancel,
		timeout:     time.Duration(cfg.UDPTimeout) * time.Second,
		mapping:     make(map[string]*PacketConn),
		packetChan:  make(chan tunnel.PacketConn, 32),
	}
	go server.packetDispatchLoop()
	log.Info("tproxy 服务器监听于", tcpListener.Addr(), "(tcp)", udpListener.LocalAddr(), "(udp)")
	log.Debug("已创建 tproxy 服务器")
	return server, nil
}
