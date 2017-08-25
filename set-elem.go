package nft

import (
	"fmt"
	"bytes"
	"syscall"
	"encoding/binary"
)

func SetElemAdd() error {
	s, lsa, err := NLSocket()
	if err != nil {
		fmt.Println("create nl socket failed")
		return err
	}
	defer NLClose(s)

	nrb := newNetlinkRequestBatchBegin()
	bnrb := nrb.Serialize(nil)

	//debug
	//fmt.Printf("batch total hdr is: ")
	//for _, i := range xwbb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println()

	//netfilter header
	//TODO: choose msg type
	nr := newNetlinkRequest(NFT_MSG_NEWSETELEM, syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)

	alen := uint32(3766492682)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	elem := elem_attr(buf.Bytes())

	fmt.Println("len of name is", len(elem), elem)

	//debug
	//fmt.Printf("batch end total hdr is: ")
	//for _, i := range xwbbe {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println()

	body := make([]byte, len(set) + len(table) + len(elem))

	tlen := 0
	copy(body[tlen:], set)
	tlen += len(set)
	copy(body[tlen:], table)
	tlen += len(table)
	copy(body[tlen:], elem)
	tlen += len(elem)

	bnr := nr.Serialize(body)

	nre := newNetlinkRequestBatchEnd()
	bnre := nre.Serialize(nil)
	//debug
	//fmt.Printf("all elem key to send: len(%d)", len(nrbb))
	//for _, i := range nrbb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println("")

	wb := make([]byte, len(bnrb) + len(bnr) + len(bnre))
	tlen = 0
	copy(wb[tlen:], bnrb)
	tlen += len(bnrb)
	copy(wb[tlen:], bnr)
	tlen += len(bnr)
	copy(wb[tlen:], bnre)

	//fmt.Println("all data len is", len(wb))
	//fmt.Printf("all data to send: ")
	//for _, i := range wb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println("")
	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return err
	}
	_, err = NLRecv(s)
	if err != nil {
		fmt.Println("nl recv failed:", err)
		return err
	}
	return nil
}

func SetElemGet() ([]byte, error) {
	return nil, nil
}

func SetElemDelete() error {
	s, lsa, err := NLSocket()
	if err != nil {
		fmt.Println("create nl socket failed")
		return err
	}
	defer NLClose(s)

	nrb := newNetlinkRequestBatchBegin()
	bnrb := nrb.Serialize(nil)
	nr := newNetlinkRequest(NFT_MSG_DELSETELEM, syscall.NLM_F_ACK)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)

	alen := uint32(3766492682)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	elem := elem_attr(buf.Bytes())

	//generate body
	body := make([]byte, len(set) + len(table) + len(elem))
	tlen := 0
	copy(body[tlen:], set)
	tlen += len(set)
	copy(body[tlen:], table)
	tlen += len(table)
	copy(body[tlen:], elem)
	tlen += len(elem)

	bnr := nr.Serialize(body)

	nre := newNetlinkRequestBatchEnd()
	bnre := nre.Serialize(nil)
	//debug
	//fmt.Printf("all elem key to send: len(%d)", len(nrbb))
	//for _, i := range nrbb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println("")

	//generate data
	wb := make([]byte, len(bnrb) + len(bnr) + len(bnre))
	tlen = 0
	copy(wb[tlen:], bnrb)
	tlen += len(bnrb)
	copy(wb[tlen:], bnr)
	tlen += len(bnr)
	copy(wb[tlen:], bnre)

	//debug
	fmt.Println("all data len is", len(wb))
	fmt.Printf("all data to send: ")
	for _, i := range wb {
		fmt.Printf("%02x ", i)
	}
	fmt.Println()

	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return err
	}
	_, err = NLRecv(s)
	if err != nil {
		fmt.Println("nl recv failed:", err)
		return err
	}

	return nil
}
