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
	//DebugOut("batch total hdr", bnrb)

	//netfilter header
	//TODO: choose msg type
	nr := newNetlinkRequest(NFT_MSG_NEWSETELEM, syscall.NLM_F_ACK | syscall.NLM_F_CREATE | syscall.NLM_F_EXCL)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)

	alen := uint32(3766492682)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	elem := elem_attr(buf.Bytes())

	//debug
	//DebugOut("batch end total hdr", )

	body := Merge(set, table, elem)

	bnr := nr.Serialize(body)
	//debug
	//DebugOut("all elem key to send", bnr)

	nre := newNetlinkRequestBatchEnd()
	bnre := nre.Serialize(nil)
	//debug
	//DebugOut("batch end total hdr", bnre)

	wb := Merge(bnrb, bnr, bnre)

	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return err
	}
	_, err = NLRecv(s, nil)
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
	body := Merge(set, table, elem)

	bnr := nr.Serialize(body)
	//debug
	//DebugOut("all elem key to send", bnr)

	nre := newNetlinkRequestBatchEnd()
	bnre := nre.Serialize(nil)

	//generate data
	wb := Merge(bnrb, bnr, bnre)

	//debug
	//DebugOut("all data to send", wb)

	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return err
	}
	_, err = NLRecv(s, nil)
	if err != nil {
		fmt.Println("nl recv failed:", err)
		return err
	}

	return nil
}
