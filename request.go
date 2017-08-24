package nft
import (
	"fmt"
	//"errors"
	//"bytes"
	//"encoding/binary"
	//"unsafe"
	"syscall"
)

func newNetlinkRequestBatchBegin() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	nr.Header.Type = NFNL_MSG_BATCH_BEGIN

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	nr.Header.Flags = syscall.NLM_F_REQUEST;
	nr.Header.Seq = uint32(0)
	NfNftMsg(&nr.NFHeader)
	return nr
}

func newNetlinkRequestBatchEnd() (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	nr.Header.Type = NFNL_MSG_BATCH_END

	nr.Header.Flags = syscall.NLM_F_REQUEST;
	nr.Header.Seq = uint32(0)
	NfNftMsg(&nr.NFHeader)
	return nr
}

func newNetlinkRequest(htype, flags uint16) (*NetlinkRequest) {
	nr := &NetlinkRequest{}
	//rr.Header.Len = uint32(syscall.NLMSG_HDRLEN + syscall.SizeofRtGenmsg)
	//fmt.Println("nlhdr len is", syscall.NLMSG_HDRLEN)
	fmt.Println("new netlink request type is", htype)
	nr.Header.Len = uint32(syscall.NLMSG_HDRLEN)
	nr.Header.Type = uint16((10 << 8) | htype) //from libnftnl/include/linux/netfilter/nf_tables.h

	//request must with NLM_F_REQUEST, with NLM_F_ACK if need ack
	// add elem
	//nr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL

	//get 
	nr.Header.Flags = flags
	//nr.Header.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_ACK
	//nr.Header.Flags = syscall.NLM_F_DUMP | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK

	nr.Header.Seq = uint32(0)
	NfIPv4Msg(&nr.NFHeader)
	//rr.Header.Pid = uint32(syscall.Getpid())
	//rr.Data.Family = uint8(family)
	//return rr.toWireFormat()
	return nr

}

