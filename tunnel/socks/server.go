package socks

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

const (
	Connect   tunnel.Command = 1
	Associate tunnel.Command = 3
)

const (
	MaxPacketSize = 1024 * 8
)

type Server struct {
	connChan         chan tunnel.Conn
	packetChan       chan tunnel.PacketConn
	underlay         tunnel.Server
	localHost        string
	localPort        int
	timeout          time.Duration
	listenPacketConn tunnel.PacketConn
	mapping          map[string]*PacketConn
	mappingLock      sync.RWMutex
	ctx              context.Context
	cancel           context.CancelFunc
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("socks 服务器已关闭")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case conn := <-s.packetChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("socks 服务器已关闭")
	}
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) handshake(conn net.Conn) (*Conn, error) {
	version := [1]byte{}
	if _, err := conn.Read(version[:]); err != nil {
		return nil, common.NewError("读取 socks 版本失败").Base(err)
	}
	if version[0] != 5 {
		return nil, common.NewError(fmt.Sprintf("无效的 socks 版本 %d", version[0]))
	}
	nmethods := [1]byte{}
	if _, err := conn.Read(nmethods[:]); err != nil {
		return nil, common.NewError("读取 NMETHODS 失败")
	}
	if _, err := io.CopyN(ioutil.Discard, conn, int64(nmethods[0])); err != nil {
		return nil, common.NewError("socks 读取方法失败").Base(err)
	}
	if _, err := conn.Write([]byte{0x5, 0x0}); err != nil {
		return nil, common.NewError("响应认证失败").Base(err)
	}

	buf := [3]byte{}
	if _, err := conn.Read(buf[:]); err != nil {
		return nil, common.NewError("读取命令失败")
	}

	addr := new(tunnel.Address)
	if err := addr.ReadFrom(conn); err != nil {
		return nil, err
	}

	return &Conn{
		metadata: &tunnel.Metadata{
			Command: tunnel.Command(buf[1]),
			Address: addr,
		},
		Conn: conn,
	}, nil
}

func (s *Server) connect(conn net.Conn) error {
	_, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return err
}

func (s *Server) associate(conn net.Conn, addr *tunnel.Address) error {
	buf := bytes.NewBuffer([]byte{0x05, 0x00, 0x00})
	common.Must(addr.WriteTo(buf))
	_, err := conn.Write(buf.Bytes())
	return err
}

func (s *Server) packetDispatchLoop() {
	for {
		buf := make([]byte, MaxPacketSize)
		n, src, err := s.listenPacketConn.ReadFrom(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				log.Debug("正在退出")
				return
			default:
				continue
			}
		}
		log.Debug("socks 从", src, "接收 UDP 数据包")
		s.mappingLock.RLock()
		conn, found := s.mapping[src.String()]
		s.mappingLock.RUnlock()
		if !found {
			ctx, cancel := context.WithCancel(s.ctx)
			conn = &PacketConn{
				input:      make(chan *packetInfo, 128),
				output:     make(chan *packetInfo, 128),
				ctx:        ctx,
				cancel:     cancel,
				PacketConn: s.listenPacketConn,
				src:        src,
			}
			go func(conn *PacketConn) {
				defer conn.Close()
				for {
					select {
					case info := <-conn.output:
						buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
						buf.Write([]byte{0, 0, 0}) // RSV, FRAG
						common.Must(info.metadata.Address.WriteTo(buf))
						buf.Write(info.payload)
						_, err := s.listenPacketConn.WriteTo(buf.Bytes(), conn.src)
						if err != nil {
							log.Error("socks 无法响应数据包到", src)
							return
						}
						log.Debug("socks 响应 UDP 数据包到", src, "元数据", info.metadata)
					case <-time.After(time.Second * 5):
						log.Info("socks UDP 会话超时，已关闭")
						s.mappingLock.Lock()
						delete(s.mapping, src.String())
						s.mappingLock.Unlock()
						return
					case <-conn.ctx.Done():
						log.Info("socks UDP 会话已关闭")
						return
					}
				}
			}(conn)

			s.mappingLock.Lock()
			s.mapping[src.String()] = conn
			s.mappingLock.Unlock()

			s.packetChan <- conn
			log.Info("socks 来自", src, "的新 UDP 会话")
		}
		r := bytes.NewBuffer(buf[3:n])
		address := new(tunnel.Address)
		if err := address.ReadFrom(r); err != nil {
			log.Error(common.NewError("socks 解析传入数据包失败").Base(err))
			continue
		}
		payload := make([]byte, MaxPacketSize)
		length, _ := r.Read(payload)
		select {
		case conn.input <- &packetInfo{
			metadata: &tunnel.Metadata{
				Address: address,
			},
			payload: payload[:length],
		}:
		default:
			log.Warn("socks UDP 队列已满")
		}
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			log.Error(common.NewError("socks 接受错误").Base(err))
			return
		}
		go func(conn net.Conn) {
			newConn, err := s.handshake(conn)
			if err != nil {
				log.Error(common.NewError("socks 与客户端握手失败").Base(err))
				return
			}
			log.Info("socks 连接来自", conn.RemoteAddr(), "元数据", newConn.metadata.String())
			switch newConn.metadata.Command {
			case Connect:
				if err := s.connect(newConn); err != nil {
					log.Error(common.NewError("socks 无法响应 CONNECT").Base(err))
					newConn.Close()
					return
				}
				s.connChan <- newConn
				return
			case Associate:
				defer newConn.Close()
				associateAddr := tunnel.NewAddressFromHostPort("udp", s.localHost, s.localPort)
				if err := s.associate(newConn, associateAddr); err != nil {
					log.Error(common.NewError("socks 无法响应 associate 请求").Base(err))
					return
				}
				buf := [16]byte{}
				newConn.Read(buf[:])
				log.Debug("socks UDP 会话结束")
			default:
				log.Error(common.NewError(fmt.Sprintf("未知的 socks 命令 %d", newConn.metadata.Command)))
				newConn.Close()
			}
		}(conn)
	}
}

// NewServer 创建一个 socks 服务器
func NewServer(ctx context.Context, underlay tunnel.Server) (tunnel.Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	listenPacketConn, err := underlay.AcceptPacket(&Tunnel{})
	if err != nil {
		return nil, common.NewError("socks 无法从底层服务器监听数据包")
	}
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay:         underlay,
		ctx:              ctx,
		cancel:           cancel,
		connChan:         make(chan tunnel.Conn, 32),
		packetChan:       make(chan tunnel.PacketConn, 32),
		localHost:        cfg.LocalHost,
		localPort:        cfg.LocalPort,
		timeout:          time.Duration(cfg.UDPTimeout) * time.Second,
		listenPacketConn: listenPacketConn,
		mapping:          make(map[string]*PacketConn),
	}
	go server.acceptLoop()
	go server.packetDispatchLoop()
	log.Debug("已创建 socks 服务器")
	return server, nil
}
