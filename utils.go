package nft
import (
	"net"
	"bytes"
	"encoding/binary"
)

func Merge(arr ...[]byte) []byte {
	tlen := 0
	for _, a := range arr {
		tlen += len(a)
	}
	ret := make([]byte, tlen)
	pos := 0
	for _, a := range arr {
		copy(ret[pos:], a)
		pos += len(a)
	}

	return ret
}

func Num2Ip(num uint32) (ip net.IP) {
    buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, num)
	bbuf := buf.Bytes()
	ip = net.IPv4(bbuf[0], bbuf[1], bbuf[2], bbuf[3])
	return
}
