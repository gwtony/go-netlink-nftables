package nft
import (
	"unsafe"
	"syscall"
)

type Nfgenmsg struct {
	NfgenFamily uint8
	Version     uint8
	ResId       uint16 // big endian
}

func NfNftMsg(nfm *Nfgenmsg) {
	nfm.NfgenFamily = syscall.AF_UNSPEC
	nfm.Version = 0 //nl.NFNETLINK_V0,
	nfm.ResId = NFNL_SUBSYS_NFTABLES
}
//func NfInetMsg() *Nfgenmsg {
//	return &Nfgenmsg{
//		NfgenFamily: syscall.AF_INET,
//		Version:     0, //nl.NFNETLINK_V0,
//		ResId:       0,
//	}
//}
func NfIPv4Msg(nfm *Nfgenmsg) {
	nfm.NfgenFamily = syscall.AF_INET //AF_INET is NFPROTO_IPV4
	nfm.Version = 0 //nl.NFNETLINK_V0,
	nfm.ResId = 0
}

func (msg *Nfgenmsg) Serialize() []byte {
	return (*(*[SizeofNfgenmsg]byte)(unsafe.Pointer(msg)))[:]
}

type NetlinkRequest struct {
	Header syscall.NlMsghdr
	NFHeader Nfgenmsg
}

func MNL_ALIGN(length int) int {
	return (((length)+SizeofNfgenmsg-1) & ^(SizeofNfgenmsg-1))
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
