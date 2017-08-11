package main
import (
	"fmt"
	"bytes"
	"encoding/binary"
	"unsafe"
	"syscall"
)
const (
    SizeofNfgenmsg      = 4
	NFNL_SUBSYS_NFTABLES = 10
)

type Nfgenmsg struct {
	NfgenFamily uint8
	Version     uint8
	ResId       uint16 // big endian
}

func (msg *Nfgenmsg) Serialize() []byte {
	return (*(*[SizeofNfgenmsg]byte)(unsafe.Pointer(msg)))[:]
}

type NetlinkRequest struct {
    Header syscall.NlMsghdr
    //Data   syscall.RtGenmsg
}

func MNL_ALIGN(length int) int {
	return (((length)+SizeofNfgenmsg-1) & ^(SizeofNfgenmsg-1))
}

// Serialize the Netlink Request into a byte array
func (nr *NetlinkRequest) Serialize(data []byte) []byte {
	length := syscall.SizeofNlMsghdr
	length = length + len(data)
	//dataBytes := make([][]byte, len(req.Data))
	//for i, data := range req.Data {
	//	dataBytes[i] = data.Serialize()
	//	length = length + len(dataBytes[i])
	//}
	//length += len(req.RawData)
	nr.Header.Len = uint32(length)

	//req.Len = uint32(length)
	b := make([]byte, length)
	hdr := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(nr)))[:]
	next := syscall.SizeofNlMsghdr
	copy(b[0:next], hdr)
	copy(b[next:length], data)
	//for _, data := range dataBytes {
	//	for _, dataByte := range data {
	//		b[next] = dataByte
	//		next = next + 1
	//	}
	//}
	//// Add the raw data if any
	//if len(req.RawData) > 0 {
	//	copy(b[next:length], req.RawData)
	//}
	return b
}

//func (rr *NetlinkRouteRequest) toWireFormat() []byte {
//	b := make([]byte, rr.Header.Len)
//	*(*uint32)(unsafe.Pointer(&b[0:4][0])) = rr.Header.Len
//	*(*uint16)(unsafe.Pointer(&b[4:6][0])) = rr.Header.Type
//	*(*uint16)(unsafe.Pointer(&b[6:8][0])) = rr.Header.Flags
//	*(*uint32)(unsafe.Pointer(&b[8:12][0])) = rr.Header.Seq
//	*(*uint32)(unsafe.Pointer(&b[12:16][0])) = rr.Header.Pid
//	//b[16] = byte(rr.Data.Family)
//	b[16] = 0x01
//	b[17] = 0x02
//	b[18] = 0x03
//	b[19] = 0x04
//	return b
//}

func newNetlinkRequest() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	//rr.Header.Type = uint16((1 << 8) | 1)
	nr.Header.Type = uint16((10 << 8) | 1) //1 means get table, from libnftnl/include/linux/netfilter/nf_tables.h

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	nr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	//rr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	nr.Header.Seq = uint32(0)
	//rr.Header.Pid = uint32(syscall.Getpid())
	//rr.Data.Family = uint8(family)
	//return rr.toWireFormat()
	return nr

}

func work() ([]byte, error) {
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		fmt.Println("socket failed")
		return nil, err
	}
	defer syscall.Close(s)
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(s, lsa); err != nil {
		fmt.Println("bind failed")
		return nil, err
	}

	//nlm := &syscall.NetlinkMessage{}
	nr := newNetlinkRequest()
	msg := &Nfgenmsg{
		NfgenFamily: syscall.AF_INET,
		Version:     0, //nl.NFNETLINK_V0,
		ResId:       0,
	}
	data := msg.Serialize()
	fmt.Println("len of nfhdr is", len(data))
	name := []byte("filter")
	name_a := make([]byte, MNL_ALIGN(len(name) + 1 + 4))

	x := uint16(len(name) + 1 + 4)
	b_buf := bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.LittleEndian, x)
	fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(name_a[0:2], b_buf.Bytes())

	x = uint16(1)
	b_buf = bytes.NewBuffer([]byte{})
	binary.Write(b_buf, binary.LittleEndian, x)
	fmt.Printf("attr type: %02x, %02x\n", b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(name_a[2:4], b_buf.Bytes())
	copy(name_a[4:], name)
	//name_a := (*(*[SizeofNfgenmsg]byte)(unsafe.Pointer(&name)))[:]

	fmt.Println("len of name is", len(name_a), name_a)
	ddd := make([]byte, len(data) + len(name_a))
	copy(ddd[0:], data)
	copy(ddd[len(data):], name_a)
	wb := nr.Serialize(ddd)
	for _, i := range wb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println("")
	fmt.Println("all data len is", len(wb))

	if err := syscall.Sendto(s, wb, 0, lsa); err != nil {
		fmt.Println("sendto failed")
		return nil, err
	}

	var tab []byte
	rbNew := make([]byte, syscall.Getpagesize())

done:
	for {
		fmt.Println("to recv")
		rb := rbNew
		nr, _, err := syscall.Recvfrom(s, rb, 0)
		if err != nil {
			fmt.Println("recv from failed")
			return nil, err
		}
		if nr < syscall.NLMSG_HDRLEN {
			fmt.Println("not header len")
			return nil, syscall.EINVAL
		}
		//fmt.Println("recv %d data", nr)
		rb = rb[:nr]
		tab = append(tab, rb...)
		msgs, err := syscall.ParseNetlinkMessage(rb)
		if err != nil {
			fmt.Println("parse message failed")
			return nil, err
		}
		for _, m := range msgs {
			lsa, err := syscall.Getsockname(s)
			if err != nil {
				fmt.Println("get sockname failed")
				return nil, err
			}
			switch lsa.(type) {
			//switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				fmt.Printf("seq is %d, pid is %d\n", m.Header.Seq, m.Header.Pid)
				fmt.Printf("data len is %d, data is %s\n", len(m.Data), string(m.Data))
				//if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
				//	fmt.Println("seq or pid not match")
				//	return nil, syscall.EINVAL
				//}
			default:
				fmt.Println("not sockaddr netlink")
				return nil, syscall.EINVAL
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("nlmsg done")
				break done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				fmt.Println("nlmsg error")
				return nil, syscall.EINVAL
			}
		}
	}
	return tab, nil
}

func main() {
	res, err := work()
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}
	fmt.Println("return is:", string(res))
}

