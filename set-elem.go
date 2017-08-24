package nft

import (
	"fmt"
	"bytes"
	"syscall"
	"encoding/binary"
)

func SetElemAdd() ([]byte, error) {
	s, lsa, err := NLSocket()
	if err != nil {
		fmt.Println("create nl socket failed")
		return nil, err
	}
	defer NLClose(s)

	nrb := newNetlinkRequestBatchBegin()
	xwbb := nrb.Serialize(nil)

	//debug
	//fmt.Printf("batch total hdr is: ")
	//for _, i := range xwbb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println()

	//netfilter header
	//TODO: choose msg type
	nr := newNetlinkRequest(NFT_MSG_NEWSETELEM, syscall.NLM_F_REQUEST | syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)
	alen := uint32(3766492682)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	elem := elem_attr(buf.Bytes())

	fmt.Println("len of name is", len(elem), elem)

	nrbe := newNetlinkRequestBatchEnd()
	xwbbe := nrbe.Serialize(nil)
	//debug
	//fmt.Printf("batch end total hdr is: ")
	//for _, i := range xwbbe {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println()

	ddd := make([]byte, len(set) + len(table) + len(elem))

	tlen := 0
	copy(ddd[tlen:], set)
	tlen += len(set)
	copy(ddd[tlen:], table)
	tlen += len(table)
	copy(ddd[tlen:], elem)
	tlen += len(elem)

	nrbb := nr.Serialize(ddd)

	//debug
	//fmt.Printf("all elem key to send: len(%d)", len(nrbb))
	//for _, i := range nrbb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println("")

	wb := make([]byte, len(xwbb) + len(nrbb) + len(xwbbe))
	tlen = 0
	copy(wb[tlen:], xwbb)
	tlen += len(xwbb)
	copy(wb[tlen:], nrbb)
	tlen += len(nrbb)
	copy(wb[tlen:], xwbbe)

	//fmt.Println("all data len is", len(wb))
	//fmt.Printf("all data to send: ")
	//for _, i := range wb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println("")
	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return nil, err
	}
	res, err := NLRecv(s)
	if err != nil {
		fmt.Println("nl recv failed:", err)
		return nil, err
	}
	return res, nil
}

func SetElemGet() ([]byte, error) {
	return nil, nil
}
