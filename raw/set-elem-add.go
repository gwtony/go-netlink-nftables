package main
import (
	"fmt"
	"bytes"
	"encoding/binary"
	"unsafe"
	"syscall"
)

const (
	NLMSG_MIN_TYPE = 0x10 //AF_UNSPEC
	NFNL_MSG_BATCH_BEGIN = NLMSG_MIN_TYPE
	NFNL_MSG_BATCH_END = NLMSG_MIN_TYPE+1
)

const (
	NLA_F_NESTED =     (1 << 15)
)
const (
    SizeofNfgenmsg      = 4
	NFNL_SUBSYS_NFTABLES = 10
)

const (
	NFTA_DATA_VALUE = 1
)

const (
	NFTA_SET_ELEM_KEY = 1
)

const (
	NFTA_SET_ELEM_LIST_TABLE = 1
	NFTA_SET_ELEM_LIST_SET = 2
	NFTA_SET_ELEM_LIST_ELEMENTS = 3
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


func newNetlinkRequestBatchBegin() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	//rr.Header.Type = uint16((1 << 8) | 1)
	nr.Header.Type = NFNL_MSG_BATCH_BEGIN //12 means set set elem, from libnftnl/include/linux/netfilter/nf_tables.h

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	nr.Header.Flags = syscall.NLM_F_REQUEST;
	//rr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	nr.Header.Seq = uint32(0)
	return nr
}

func newNetlinkRequestBatchEnd() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	//rr.Header.Type = uint16((1 << 8) | 1)
	nr.Header.Type = NFNL_MSG_BATCH_END //12 means set set elem, from libnftnl/include/linux/netfilter/nf_tables.h

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	nr.Header.Flags = syscall.NLM_F_REQUEST;
	//rr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	nr.Header.Seq = uint32(0)
	return nr
}

func newNetlinkRequest() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	//rr.Header.Type = uint16((1 << 8) | 1)
	nr.Header.Type = uint16((10 << 8) | 12) //12 means set set elem, from libnftnl/include/linux/netfilter/nf_tables.h

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	nr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL
	//rr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	nr.Header.Seq = uint32(0)
	//rr.Header.Pid = uint32(syscall.Getpid())
	//rr.Data.Family = uint8(family)
	//return rr.toWireFormat()
	return nr

}

func attrz(name []byte, attrType int) []byte {
	nlen := len(name)
	attr := make([]byte, MNL_ALIGN(nlen + 1 + 4)) //4 is attr hdr len

	alen := uint16(nlen + 1 + 4)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[0:2], buf.Bytes())

	atype := uint16(attrType)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, atype)
	//fmt.Printf("attr type: %02x, %02x\n", b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[2:4], buf.Bytes())
	copy(attr[4:], name)
	fmt.Printf("len(%d), name(%s): ", len(attr), string(name))
	for _, ai := range attr {
		fmt.Printf("%02x ", ai)
	}
	fmt.Println("")

	return attr
}

func attr(name []byte, attrType int) []byte {
	nlen := len(name)
	attr := make([]byte, MNL_ALIGN(nlen + 4)) //4 is attr hdr len

	alen := uint16(nlen + 4)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[0:2], buf.Bytes())

	atype := uint16(attrType)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, atype)
	//fmt.Printf("attr type: %02x, %02x\n", b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[2:4], buf.Bytes())
	copy(attr[4:], name)
	fmt.Printf("len(%d), name(%s): ", len(attr), string(name))
	for _, ai := range attr {
		fmt.Printf("%02x ", ai)
	}
	fmt.Println("")

	return attr
}

func elem_attr(name []byte) []byte {
	datav := attr(name, NFTA_DATA_VALUE)
	keyv := attr(datav, NLA_F_NESTED | NFTA_SET_ELEM_KEY)
	idxv := attr(keyv, NLA_F_NESTED | 1) //index begin from 1
	elem := attr(idxv, NFTA_SET_ELEM_LIST_ELEMENTS | NLA_F_NESTED)
	return elem
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
	nrb := newNetlinkRequestBatchBegin()
	msgb := &Nfgenmsg{
		NfgenFamily: syscall.AF_UNSPEC,
		Version:     0, //nl.NFNETLINK_V0,
		ResId:       10, //NFNL_SUBSYS_NFTABLES
	}
	nfhdrb := msgb.Serialize()
	fmt.Println("len of nfhdr batch is", len(nfhdrb))
	xwbb := nrb.Serialize(nfhdrb)
	fmt.Printf("batch total hdr is: ")
	for _, i := range xwbb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println()

	//netfilter header
	nr := newNetlinkRequest()
	msg := &Nfgenmsg{
		NfgenFamily: syscall.AF_INET,
		Version:     0, //nl.NFNETLINK_V0,
		ResId:       0,
	}
	nfhdr := msg.Serialize()
	fmt.Println("len of nfhdr is", len(nfhdr))
	xwb := nr.Serialize(nfhdr)
	fmt.Printf("total hdr is: ")
	for _, i := range xwb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println()

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)
	alen := uint32(3766492682)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	elem := elem_attr(buf.Bytes())

	//name_a := (*(*[SizeofNfgenmsg]byte)(unsafe.Pointer(&name)))[:]
	fmt.Println("len of name is", len(elem), elem)

	nrbe := newNetlinkRequestBatchEnd()
	msgbe := &Nfgenmsg{
		NfgenFamily: syscall.AF_UNSPEC,
		Version:     0, //nl.NFNETLINK_V0,
		ResId:       10, //NFNL_SUBSYS_NFTABLES
	}
	nfhdrbe := msgbe.Serialize()
	fmt.Println("len of nfhdr batch is", len(nfhdrbe))
	xwbbe := nrbe.Serialize(nfhdrbe)
	fmt.Printf("batch end total hdr is: ")
	for _, i := range xwbbe {
		fmt.Printf("%02x ", i)
	}
	fmt.Println()

	ddd := make([]byte, len(nfhdr) + len(set) + len(table) + len(elem))

	tlen := 0
	//copy(ddd[tlen:], xwbb)
	//tlen += len(xwbb)
	copy(ddd[tlen:], nfhdr)
	tlen += len(nfhdr)
	copy(ddd[tlen:], set)
	tlen += len(set)
	copy(ddd[tlen:], table)
	tlen += len(table)
	copy(ddd[tlen:], elem)
	tlen += len(elem)
	//copy(ddd[tlen:], xwbbe)
	//tlen += len(xwbbe)

	nrbb := nr.Serialize(ddd)

	fmt.Printf("all elem key to send: len(%d)", len(nrbb))
	for _, i := range nrbb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println("")

	wb := make([]byte, len(xwbb) + len(nrbb) + len(xwbbe))
	tlen = 0
	copy(wb[tlen:], xwbb)
	tlen += len(xwbb)
	copy(wb[tlen:], nrbb)
	tlen += len(nrbb)
	copy(wb[tlen:], xwbbe)

	fmt.Println("all data len is", len(wb))
	fmt.Printf("all data to send: ")
	for _, i := range wb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println("")

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
				fmt.Println(m)
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

