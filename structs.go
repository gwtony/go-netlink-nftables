package nft
import (
	"fmt"
	"bytes"
	"unsafe"
	"syscall"
	"encoding/binary"
)

type Nfgenmsg struct {
	Nfgenfamily uint8
	Version     uint8
	Resid       uint16 // big endian
}

func NfNftMsg(nfm *Nfgenmsg) {
	nfm.Nfgenfamily = syscall.AF_UNSPEC
	nfm.Version = 0 //nl.NFNETLINK_V0,
	nfm.Resid = NFNL_SUBSYS_NFTABLES
}
//func NfInetMsg() *Nfgenmsg {
//	return &Nfgenmsg{
//		NfgenFamily: syscall.AF_INET,
//		Version:     0, //nl.NFNETLINK_V0,
//		ResId:       0,
//	}
//}
func NfIPv4Msg(nfm *Nfgenmsg) {
	nfm.Nfgenfamily = syscall.AF_INET //AF_INET is NFPROTO_IPV4
	nfm.Version = 0 //nl.NFNETLINK_V0,
	nfm.Resid = 0
}

func (msg *Nfgenmsg) Serialize() []byte {
	//BigEndian
	return (*(*[SizeofNfgenmsg]byte)(unsafe.Pointer(msg)))[:]
}

type NetlinkRequest struct {
	Header syscall.NlMsghdr
	NFHeader Nfgenmsg
}

func MNL_ALIGN(length int) int {
	return (((length)+SizeofNfgenmsg-1) & ^(SizeofNfgenmsg-1))
}

var HTOLEN Nfgenmsg
func MNL_NLMSG_HDRLEN() int {
	return MNL_ALIGN(binary.Size(HTOLEN))
}

// Serialize the Netlink Request into a byte array
func (nr *NetlinkRequest) Serialize(data []byte) []byte {
	length := syscall.SizeofNlMsghdr
	bnfh := nr.NFHeader.Serialize()
	lnfh := len(bnfh)
	length = length + lnfh + len(data)

	nr.Header.Len = uint32(length)

	b := make([]byte, length)
	hdr := (*(*[syscall.SizeofNlMsghdr]byte)(unsafe.Pointer(nr)))[:]
	next := syscall.SizeofNlMsghdr
	copy(b[0:next], hdr)
	copy(b[next:next + lnfh], bnfh)
	next += lnfh
	copy(b[next:length], data)

	//For debug
	//DebugOut("nr serialize", b)

	return b
}

func parseNfgenmsg(data []byte) (*Nfgenmsg, error) {
	var family, version uint8
	var resid uint16

	nfm := &Nfgenmsg{}

	tbr := bytes.NewReader(data[0:1])
	err := binary.Read(tbr, binary.BigEndian, &family)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return nil, err
	}
	nfm.Nfgenfamily = family

	tbr = bytes.NewReader(data[1:2])
	err = binary.Read(tbr, binary.BigEndian, &version)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return nil, err
	}
	nfm.Version = version

	tbr = bytes.NewReader(data[2:4])
	err = binary.Read(tbr, binary.BigEndian, &resid)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return nil, err
	}
	nfm.Resid = resid

	return nfm, nil
}
