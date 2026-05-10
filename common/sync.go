package common

// Notifier 是一个用于通知变化的工具。变更生产者可以多次通知变更，消费者可以异步接收到通知。
type Notifier struct {
	c chan struct{}
}

// NewNotifier 创建一个新的通知器。
func NewNotifier() *Notifier {
	return &Notifier{
		c: make(chan struct{}, 1),
	}
}

// Signal 发送变更信号，通常由生产者调用。此方法永远不会阻塞。
func (n *Notifier) Signal() {
	select {
	case n.c <- struct{}{}:
	default:
	}
}

// Wait 返回一个用于等待变化的通道。返回的通道永远不会关闭。
func (n *Notifier) Wait() <-chan struct{} {
	return n.c
}
