package mux

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

type muxID uint32

func generateMuxID() muxID {
	return muxID(rand.Uint32())
}

type smuxClientInfo struct {
	id             muxID
	client         *smux.Session
	lastActiveTime time.Time
	underlayConn   tunnel.Conn
}

// Client 是一个 smux 客户端
type Client struct {
	clientPoolLock sync.Mutex
	clientPool     map[muxID]*smuxClientInfo
	underlay       tunnel.Client
	concurrency    int
	timeout        time.Duration
	ctx            context.Context
	cancel         context.CancelFunc
}

func (c *Client) Close() error {
	c.cancel()
	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()
	for id, info := range c.clientPool {
		info.client.Close()
		log.Debug("mux 客户端", id, "已关闭")
	}
	return nil
}

func (c *Client) cleanLoop() {
	var checkDuration time.Duration
	if c.timeout <= 0 {
		checkDuration = time.Second * 10
		log.Warn("负的 mux 超时")
	} else {
		checkDuration = c.timeout / 4
	}
	log.Debug("检查间隔:", checkDuration.Seconds(), "秒")
	ticker := time.NewTicker(checkDuration)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.clientPoolLock.Lock()
			for id, info := range c.clientPool {
				if info.client.IsClosed() {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
					log.Info("mux 客户端", id, "已死亡")
				} else if info.client.NumStreams() == 0 && time.Since(info.lastActiveTime) > c.timeout {
					info.client.Close()
					info.underlayConn.Close()
					delete(c.clientPool, id)
					log.Info("mux 客户端", id, "因不活动已关闭")
				}
			}
			log.Debug("当前 mux 客户端数量: ", len(c.clientPool))
			for id, info := range c.clientPool {
				log.Debug(fmt.Sprintf("  - %x: %d/%d", id, info.client.NumStreams(), c.concurrency))
			}
			c.clientPoolLock.Unlock()
		case <-c.ctx.Done():
			log.Debug("正在关闭 mux 清理器...")
			c.clientPoolLock.Lock()
			for id, info := range c.clientPool {
				info.client.Close()
				info.underlayConn.Close()
				delete(c.clientPool, id)
				log.Debug("mux 客户端", id, "已关闭")
			}
			c.clientPoolLock.Unlock()
			return
		}
	}
}

func (c *Client) newMuxClient() (*smuxClientInfo, error) {
	// 调用此函数时必须锁定互斥锁
	id := generateMuxID()
	if _, found := c.clientPool[id]; found {
		return nil, common.NewError("重复的 ID")
	}

	fakeAddr := &tunnel.Address{
		DomainName:  "MUX_CONN",
		AddressType: tunnel.DomainName,
	}
	conn, err := c.underlay.DialConn(fakeAddr, &Tunnel{})
	if err != nil {
		return nil, common.NewError("mux 拨号失败").Base(err)
	}
	conn = newStickyConn(conn)

	smuxConfig := smux.DefaultConfig()
	// smuxConfig.KeepAliveDisabled = true
	client, _ := smux.Client(conn, smuxConfig)
	info := &smuxClientInfo{
		client:         client,
		underlayConn:   conn,
		id:             id,
		lastActiveTime: time.Now(),
	}
	c.clientPool[id] = info
	return info, nil
}

func (c *Client) DialConn(*tunnel.Address, tunnel.Tunnel) (tunnel.Conn, error) {
	createNewConn := func(info *smuxClientInfo) (tunnel.Conn, error) {
		rwc, err := info.client.Open()
		info.lastActiveTime = time.Now()
		if err != nil {
			info.underlayConn.Close()
			info.client.Close()
			delete(c.clientPool, info.id)
			return nil, common.NewError("mux 无法从客户端打开流").Base(err)
		}
		return &Conn{
			rwc:  rwc,
			Conn: info.underlayConn,
		}, nil
	}

	c.clientPoolLock.Lock()
	defer c.clientPoolLock.Unlock()
	for _, info := range c.clientPool {
		if info.client.IsClosed() {
			delete(c.clientPool, info.id)
			log.Info(fmt.Sprintf("Mux 客户端 %x 已关闭", info.id))
			continue
		}
		if info.client.NumStreams() < c.concurrency || c.concurrency <= 0 {
			return createNewConn(info)
		}
	}

	info, err := c.newMuxClient()
	if err != nil {
		return nil, common.NewError("未找到可用的 mux 客户端").Base(err)
	}
	return createNewConn(info)
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("不支持")
}

func NewClient(ctx context.Context, underlay tunnel.Client) (*Client, error) {
	clientConfig := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	client := &Client{
		underlay:    underlay,
		concurrency: clientConfig.Mux.Concurrency,
		timeout:     time.Duration(clientConfig.Mux.IdleTimeout) * time.Second,
		ctx:         ctx,
		cancel:      cancel,
		clientPool:  make(map[muxID]*smuxClientInfo),
	}
	go client.cleanLoop()
	log.Debug("已创建 mux 客户端")
	return client, nil
}
