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
	elem := elemAttr(buf.Bytes())

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

func SetElemGet() error {
	s, lsa, err := NLSocket()
	if err != nil {
		fmt.Println("create nl socket failed")
		return err
	}
	defer NLClose(s)

	nr := newNetlinkRequest(NFT_MSG_GETSETELEM, NLM_F_DUMP | NLM_F_ACK)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)
	wb := nr.Serialize(table)

	//debug
	//DebugOut("all data to send", wb)

	err = NLSend(s, wb, 0, lsa)
	if err != nil {
		fmt.Println("nl send failed:", err)
		return err
	}
	err = NLRecv(s, SetElemGetCb)
	if err != nil {
		fmt.Println("nl recv failed:", err)
		return err
	}

	return nil
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
	elem := elemAttr(buf.Bytes())

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

type NLSet struct {
	Family  uint32
	Flags   uint32
	Id      uint32
	Table   string
	Name    string
	KeyType int32
	ElementList []SetElement
}

type NLSetElem struct {
	//TODO
}

func SetElemMsgParse(nm *syscall.NetlinkMessage) (*NLSet, error) {
	var family, version uint8
	var id uint16
	nls := &NLSet{}
	bnfm := mn.Data[:MNL_NLMSG_HDRLEN]
	am := make(attrmap, 1)

	nfm, err := parseNfgenmsg(bnfm)
	if err != nil {
		fmt.Println("parse nfgenmsg failed")
		return nil, err
	}

	fmt.Println("nftgenmsg is ", nfm)
	anla, err := attrParse(mn.Data[MNL_NLMSG_HDRLEN:], setElemParseAttrCb)
	if err != nil {
		fmt.Println("parse attr failed")
		return nil, err
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_TABLE]; ok {
		//TODO: check nls.table
		nls.Table, err = attrGetStr(i)
		if err != nil {
			return nil, err
		}
		nls.Flags |= (1 << NFTNL_SET_TABLE)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_SET]; ok {
		//TODO: check nls.name
		nls.Name, err = attrGetStr(i)
		if err != nil {
			return nil, err
		}
		nls.Flags |= (1 << NFTA_SET_ELEM_LIST_SET)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_SET_ID]; ok {
		nls.Id, err = attrGetU32(i)
		if err != nil {
			return nil, err
		}
		nls.Id |= (1 << NFTA_SET_ELEM_LIST_SET_ID)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_ELEMENTS]; ok {
		ret = SetElemParse(nls, i)
		if ret < 0 {
			return nil, errors.New("elem parse error")
		}
	}
	//...
	nls.Family = nfm.Nfgenfamily
	nls.Flags |= (1 << NFTNL_SET_FAMILY)

	return nls, nil
}

func SetElemParse(nls *NLS, attr *nlattr) int {
	left := 0
	pos := 0

	battr := attrGetPayload(attr)
	for {
		nattr, err := attrParseFromBuffer(battr, pos)
		if err != nil {
			return -1
		}
		left = len(battr) - nattr.nlaLen
		if !attrOk(nattr, left) {
			break
		}
		//TODO:
		atype := attrGetType(nattr)
		if atype != NFTA_LIST_ELEM {
			return -1
		}
		ret = SetElemParse2(nls, nattr)
		if ret < 0 {
			return ret
		}

		pos += nattr.nlaLen
		if pos >= len(battr) {
			break
		}
	}

	return 0
}

func SetElemParse2(nls *NLS, attr *nlattr) int {
	am := make(attrmap, 1)
	
}

func SetElemGetCb(nm syscall.NetlinkMessage) (int, error) {
	ret, err := SetElemMsgParse(&nm)
	if err != nil {
		//TODO: return some
		return MNL_CB_OK, nil
	}
	return MNL_CB_OK, nil
}

func setElemParseAttrCb(attr *nlattr, am *attrmap) int {
	atype := attrGetType(attr)
	if attrTypeIsValid(attr, NFTA_SET_ELEM_LIST_MAX) {
		return MNL_CB_OK
	}
	switch(atype) {
	case NFTA_SET_ELEM_LIST_TABLE:
	case NFTA_SET_ELEM_LIST_SET:
		if ret, err := attrIsValid(attr, MNL_TYPE_STRING); err != nil {
			//TODO: abi_breakage?
			return ret
		}
	case NFTA_SET_ELEM_LIST_ELEMENTS:
		if ret, err := attrIsValid(attr, MNL_TYPE_NESTED); err != nil {
			//TODO: abi_breakage?
			return ret
		}
	}

	am[atype] = attr

	return MNL_CB_OK
}
