//go:build linux
// +build linux

package tproxy

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// Listener 描述一个 TCP 监听器
// 在监听套接字上定义了 Linux IP_TRANSPARENT 选项
type Listener struct {
	base net.Listener
}

// Accept 等待并返回
// 到监听器的下一个连接。
//
// 此命令包装 Listener
// 的 AcceptTProxy 方法
func (listener *Listener) Accept() (net.Conn, error) {
	tcpConn, err := listener.base.(*net.TCPListener).AcceptTCP()
	if err != nil {
		return nil, err
	}

	return tcpConn, nil
}

// Addr 返回网络地址
// 监听器正在接受连接
func (listener *Listener) Addr() net.Addr {
	return listener.base.Addr()
}

// Close 将关闭监听器，不再接受
// 任何更多连接。任何阻塞的连接
// 将解除阻塞并关闭
func (listener *Listener) Close() error {
	return listener.base.Close()
}

// ListenTCP 将构建一个新的 TCP 监听器
// 底层套接字上设置了 Linux IP_TRANSPARENT 选项
func ListenTCP(network string, laddr *net.TCPAddr) (net.Listener, error) {
	listener, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	fileDescriptorSource, err := listener.File()
	if err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("获取文件描述符: %s", err)}
	}
	defer fileDescriptorSource.Close()

	if err = syscall.SetsockoptInt(int(fileDescriptorSource.Fd()), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return nil, &net.OpError{Op: "listen", Net: network, Source: nil, Addr: laddr, Err: fmt.Errorf("设置套接字选项: IP_TRANSPARENT: %s", err)}
	}

	return &Listener{listener}, nil
}

const (
	IP6T_SO_ORIGINAL_DST = 80
	SO_ORIGINAL_DST      = 80
)

// getOriginalTCPDest 从 NATed 连接中检索原始目标地址。
// 目前仅支持使用 DNAT/REDIRECT 的 Linux iptables。
// 对于其他操作系统，这将只返回 conn.LocalAddr()。
//
// 请注意，此函数仅在 nf_conntrack_ipv4 和/或
// nf_conntrack_ipv6 加载到内核中时有效。
func getOriginalTCPDest(conn *net.TCPConn) (*net.TCPAddr, error) {
	f, err := conn.File()
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fd := int(f.Fd())
	// 恢复到非阻塞模式。
	// 请参阅 http://stackoverflow.com/a/28968431/1493661
	if err = syscall.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	v6 := conn.LocalAddr().(*net.TCPAddr).IP.To4() == nil
	if v6 {
		var addr syscall.RawSockaddrInet6
		var len uint32
		len = uint32(unsafe.Sizeof(addr))
		err = getsockopt(fd, syscall.IPPROTO_IPV6, IP6T_SO_ORIGINAL_DST,
			unsafe.Pointer(&addr), &len)
		if err != nil {
			return nil, os.NewSyscallError("getsockopt", err)
		}
		ip := make([]byte, 16)
		for i, b := range addr.Addr {
			ip[i] = b
		}
		pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
		return &net.TCPAddr{
			IP:   ip,
			Port: int(pb[0])*256 + int(pb[1]),
		}, nil
	}

	// IPv4
	var addr syscall.RawSockaddrInet4
	var len uint32
	len = uint32(unsafe.Sizeof(addr))
	err = getsockopt(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST,
		unsafe.Pointer(&addr), &len)
	if err != nil {
		return nil, os.NewSyscallError("getsockopt", err)
	}
	ip := make([]byte, 4)
	for i, b := range addr.Addr {
		ip[i] = b
	}
	pb := *(*[2]byte)(unsafe.Pointer(&addr.Port))
	return &net.TCPAddr{
		IP:   ip,
		Port: int(pb[0])*256 + int(pb[1]),
	}, nil
}
