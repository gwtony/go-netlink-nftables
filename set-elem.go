package nft

import (
	"fmt"
	"bytes"
	"errors"
	"syscall"
	"encoding/binary"
)

const (
	NFTNL_SET_ELEM_FLAGS = iota
	NFTNL_SET_ELEM_KEY
	NFTNL_SET_ELEM_VERDICT
	NFTNL_SET_ELEM_CHAIN
	NFTNL_SET_ELEM_DATA
	NFTNL_SET_ELEM_TIMEOUT
	NFTNL_SET_ELEM_EXPIRATION
	NFTNL_SET_ELEM_USERDATA
	NFTNL_SET_ELEM_EXPR
	NFTNL_SET_ELEM_OBJREF
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
	err = NLRecv(s, nil)
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

	nr := newNetlinkRequest(NFT_MSG_GETSETELEM, syscall.NLM_F_DUMP | syscall.NLM_F_ACK)

	set := attrz([]byte("bh"), NFTA_SET_ELEM_LIST_SET)
	table := attrz([]byte("filter"), NFTA_SET_ELEM_LIST_TABLE)

	body := Merge(set, table)
	wb := nr.Serialize(body)

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
	err = NLRecv(s, nil)
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
	ElementList []NLSetElem
}

type NLSetElem struct {
	Flags uint32
	Key	NftDatareg
	Data NftDatareg
}

func SetElemMsgParse(nm *syscall.NetlinkMessage) (*NLSet, error) {
	//var family, version uint8
	//var id uint16
	nls := &NLSet{}
	bnfm := nm.Data[:MNL_NLMSG_HDRLEN()]
	am := make(attrmap, 1)

	nfm, err := parseNfgenmsg(bnfm)
	if err != nil {
		fmt.Println("parse nfgenmsg failed")
		return nil, err
	}

	fmt.Println("nftgenmsg is ", nfm)
	fmt.Printf("nm data len is %d\n", len(nm.Data))
	_, err = attrParse(nm.Data[MNL_NLMSG_HDRLEN():], setElemListParseAttrCb, am)
	if err != nil {
		fmt.Println("parse attr failed")
		return nil, err
	}
	fmt.Println("after attr parse")
	if i, ok := am[NFTA_SET_ELEM_LIST_TABLE]; ok {
		//TODO: check nls.table
		nls.Table = attrGetStr(i)
		fmt.Println("attr parse table is", nls.Table)
		nls.Flags |= (1 << NFTNL_SET_TABLE)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_SET]; ok {
		//TODO: check nls.name
		nls.Name = attrGetStr(i)
		fmt.Println("attr parse name is", nls.Name)
		nls.Flags |= (1 << NFTA_SET_ELEM_LIST_SET)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_SET_ID]; ok {
		nls.Id = attrGetU32(i)
		fmt.Println("attr parse id is", nls.Id)
		nls.Flags |= (1 << NFTA_SET_ELEM_LIST_SET_ID)
	}
	if i, ok := am[NFTA_SET_ELEM_LIST_ELEMENTS]; ok {
		fmt.Println("attr parse got list elements")
		ret := SetElemParse(nls, i)
		if ret < 0 {
			return nil, errors.New("elem parse error")
		}
	}
	//...
	nls.Family = uint32(nfm.Nfgenfamily)
	nls.Flags |= (1 << NFTNL_SET_FAMILY)
	fmt.Println("return nls:", nls)

	return nls, nil
}

func SetElemParse(nls *NLSet, attr *nlattr) int {
	left := 0
	pos := 0
	fmt.Println("in set elem parse")

	battr := attrGetPayload(attr)
	for {
		nattr, err := attrParseFromBuffer(battr, pos)
		if err != nil {
			fmt.Println("attr parse from buffer failed")
			return -1
		}
		//left = len(battr) - int(nattr.nlaLen)
		left = int(nattr.nlaLen)
		fmt.Println("set elem parse buf left is", left)
		if !attrOk(nattr, left) {
			fmt.Println("attr not ok")
			break
		}
		//TODO:
		atype := attrGetType(nattr)
		if atype != NFTA_LIST_ELEM {
			return -1
		}
		ret := SetElemParse2(nls, nattr)
		if ret < 0 {
			fmt.Println("set elem parse2 failed")
			return ret
		}

		pos += MNL_ALIGN(int(nattr.nlaLen))
		if pos >= len(battr) {
			break
		}
	}

	return 0
}

func SetElemParse2(nls *NLSet, attr *nlattr) int {
	var rtype int
	am := make(attrmap, 1)
	e := &NLSetElem{}

	fmt.Println("in set elem parse2")

	ret, err := attrParseNested(attr, setElemParseAttrCb, am)
	if err != nil {
		return ret
	}
	if i, ok := am[NFTA_SET_ELEM_FLAGS]; ok {
		//TODO: e.SetElemFlags = ntohl(mnl_attr_get_u32(tb[NFTA_SET_ELEM_FLAGS]));
		fmt.Println("case NFTA_SET_ELEM_FLAGS", i)
		e.Flags |= (1 << NFTNL_SET_ELEM_FLAGS)
	}
	if i, ok := am[NFTA_SET_ELEM_TIMEOUT]; ok {
		//TODO: e->timeout = be64toh(mnl_attr_get_u64(tb[NFTA_SET_ELEM_TIMEOUT]))
		fmt.Println("case NFTA_SET_ELEM_TIMEOUT", i)
		e.Flags |= (1 << NFTNL_SET_ELEM_TIMEOUT)
	}
	if i, ok := am[NFTA_SET_ELEM_EXPIRATION]; ok {
		//TODO: e->expiration = be64toh(mnl_attr_get_u64(tb[NFTA_SET_ELEM_EXPIRATION]));
		fmt.Println("case NFTA_SET_ELEM_EXPIRATION", i)
		e.Flags |= (1 << NFTNL_SET_ELEM_EXPIRATION)
	}
	if i, ok := am[NFTA_SET_ELEM_KEY]; ok {
		//TODO: parse data
		rtype, ret = NftnlParseData(&e.Key, i)
		if ret < 0 {
			return ret
		}
		fmt.Println("case NFTA_SET_ELEM_KEY", i)
		e.Flags |= (1 << NFTNL_SET_ELEM_KEY)
	}
	if i, ok := am[NFTA_SET_ELEM_DATA]; ok {
		//TODO: parse data
		rtype, ret = NftnlParseData(&e.Data, i)
		if ret < 0 {
			return ret
		}
		fmt.Println("case NFTA_SET_ELEM_DATA", i)
		switch(rtype) {
		case DATA_VERDICT:
			e.Flags |= (1 << NFTNL_SET_ELEM_VERDICT)
		case DATA_CHAIN:
			e.Flags |= (1 << NFTNL_SET_ELEM_VERDICT) | (1 << NFTNL_SET_ELEM_CHAIN)
		case DATA_VALUE:
			e.Flags |= (1 << NFTNL_SET_ELEM_DATA)
		}
	}
	if i, ok := am[NFTA_SET_ELEM_EXPR]; ok {
		//TODO
		fmt.Println("case NFTA_SET_ELEM_EXPR", i)
	}
	if i, ok := am[NFTA_SET_ELEM_USERDATA]; ok {
		//TODO
		fmt.Println("case NFTA_SET_ELEM_USERDATA", i)
	}
	if i, ok := am[NFTA_SET_ELEM_OBJREF]; ok {
		//TODO
		fmt.Println("case NFTA_SET_ELEM_OBJREF", i)
	}
	//TODO: list add tail
	return 0
}

func SetElemGetCb(nm syscall.NetlinkMessage) (int, error) {
	fmt.Println("in set elem get cb")
	_, err := SetElemMsgParse(&nm)
	if err != nil {
		//TODO: return some
		return MNL_CB_OK, nil
	}
	return MNL_CB_OK, nil
}

func setElemListParseAttrCb(attr *nlattr, am attrmap) int {
	fmt.Println("in set elem list parse attr cb")
	atype := attrGetType(attr)
	if _, err := attrTypeIsValid(attr, NFTA_SET_ELEM_LIST_MAX); err != nil {
		return MNL_CB_OK
	}
	switch(atype) {
	case NFTA_SET_ELEM_LIST_TABLE, NFTA_SET_ELEM_LIST_SET:
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

func setElemParseAttrCb(attr *nlattr, am attrmap) int {
	fmt.Println("in set elem parse attr cb")
	atype := attrGetType(attr)
	if _, err := attrTypeIsValid(attr, NFTA_SET_MAX); err != nil {
		fmt.Println("setElemParseAttrCb not valid")
		return MNL_CB_OK
	}
	switch(atype) {
	case NFTA_SET_ELEM_FLAGS:
		if ret, err := attrIsValid(attr, MNL_TYPE_U32); err != nil {
			//TODO: exit
			fmt.Println("setElemParseAttrCb case NFTA_SET_ELEM_FLAGS not valid")
			return ret
		}
	case NFTA_SET_ELEM_TIMEOUT, NFTA_SET_ELEM_EXPIRATION:
		if ret, err := attrIsValid(attr, MNL_TYPE_U64); err != nil {
			//TODO: exit
			fmt.Println("setElemParseAttrCb case NFTA_SET_ELEM_TIMEOUT not valid")
			return ret
		}
	case NFTA_SET_ELEM_KEY, NFTA_SET_ELEM_DATA, NFTA_SET_ELEM_EXPR:
		if ret, err := attrIsValid(attr, MNL_TYPE_NESTED); err != nil {
			//TODO: exit
			fmt.Println("setElemParseAttrCb case NFTA_SET_ELEM_KEY... not valid")
			return ret
		}
	case NFTA_SET_ELEM_USERDATA:
		if ret, err := attrIsValid(attr, MNL_TYPE_BINARY); err != nil {
			//TODO: exit
			fmt.Println("setElemParseAttrCb case NFTA_SET_ELEM_USERDATA not valid")
			return ret
		}
	}


	fmt.Println("setElemParseAttrCb all pass")

	am[atype] = attr
	return MNL_CB_OK
}
