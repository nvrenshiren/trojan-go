// 类似缓冲区的字节切片
// Copyright (c) 2017 Fadhli Dzil Ikram

package buffer

// Buffer 类型封装byte slice内置类型
type Buffer []byte

// Reset 将缓冲区位置重置到开始
func (b *Buffer) Reset() {
	*b = Buffer([]byte(*b)[:0])
}

// Append 将字节切片追加到缓冲区
func (b *Buffer) Append(data []byte) {
	*b = append(*b, data...)
}

// AppendByte 追加单个字节到缓冲区
func (b *Buffer) AppendByte(data byte) {
	*b = append(*b, data)
}

// AppendInt 追加整数到缓冲区
func (b *Buffer) AppendInt(val int, width int) {
	var repr [8]byte
	reprCount := len(repr) - 1
	for val >= 10 || width > 1 {
		reminder := val / 10
		repr[reprCount] = byte('0' + val - reminder*10)
		val = reminder
		reprCount--
		width--
	}
	repr[reprCount] = byte('0' + val)
	b.Append(repr[reprCount:])
}

// Bytes 返回底层切片数据
func (b Buffer) Bytes() []byte {
	return []byte(b)
}
