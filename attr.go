package nft
import (
	"fmt"
	"errors"
	"bytes"
	"encoding/binary"
	//"unsafe"
	"syscall"
)

const (
	NLATTR_LEN = 4
)

type nlattr struct {
	nlaLen     uint16
	nlaType    uint16
	nlaPayload []byte
}
type attrmap map[int]*nlattr

//type attrDataTypeLen []

type attrcb func(nla *nlattr, am *attrmap) int

func attrz(name []byte, attrType int) []byte {
	nlen := len(name)
	attr := make([]byte, MNL_ALIGN(nlen + 1 + 4)) //4 is attr hdr len

	alen := uint16(nlen + 1 + 4)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	//fmt.Println()
	copy(attr[0:2], buf.Bytes())

	atype := uint16(attrType)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, atype)
	//fmt.Printf("attr type: %02x, %02x\n", b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[2:4], buf.Bytes())
	copy(attr[4:], name)

	//debug
	//DebugOut("attrz", attr)

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

	//debug
	//DebugOut("attr", attr)

	return attr
}

func elemAttr(name []byte) []byte { //TODO: change
	datav := attr(name, NFTA_DATA_VALUE)
	keyv := attr(datav, syscall.NLA_F_NESTED | NFTA_SET_ELEM_KEY)
	idxv := attr(keyv, syscall.NLA_F_NESTED | 1) //index begin from 1
	elem := attr(idxv, NFTA_SET_ELEM_LIST_ELEMENTS | syscall.NLA_F_NESTED)
	return elem
}

func getPayloadOffset(offset uint32) uint32 {
	return MNL_NLMSG_HDRLEN + MNL_ALIGN(offset)
}

func attrOk(nla *nlattr, dlen int) bool {
	return dlen >= NLATTR_LEN && int(nla->nlaLen) >= NLATTR_LEN && int(nla->nlaLen) <= dlen
}

func attrParseFromBuffer(data []byte, pos int) (*nlattr, error) {
	nla := &nlattr{}

	tbr := bytes.NewReader(data[pos : pos + 2])
	err := binary.Read(tbr, binary.LittleEndian, &nlaLen)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return nil, err
	}
	nla.nlaLen = nlaLen

	tbr = bytes.NewReader(data[pos + 2 : pos + 4])
	err = binary.Read(tbr, binary.LittleEndian, &nlaType)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return nil, err
	}
	nla.nlaType = nlaType

	pos += 4
	nla.nlaPayload = data[pos: nla.nlaLen]

	return nla, nil
}

func attrParse(data []byte, cb attrcb, am *attrmap) ([]nlattr, error) {
	var anla []*nlattr
	var nlaLen, nlaType uint16

	pos := 0
	dlen := len(data)

	for {
		nla, err := attrParseFromBuffer(data, pos)
		if err != nil {
			return nil, err
		}

		if !attrOk(nla, dlen) {
			break
		}

		ret, err := cb(nla, am)
		if err != nil {
			return nil, err
		}
		if ret <= MNL_CB_STOP {
			return nil, errors.New("parse attr failed")
		}

		anla = append(anla, nla)

		if pos >= dlen {
			break
		}
	}

	return anla, nil
}

func attrGetType(nla *nlattr) uint16 {
	return nla.nlaType & NLA_TYPE_MASK
}

func attrTypeIsValid(nla *nlattr, max uint16) (int, error) {
	if attrGetType(nla) > max {
		return -1, syscall.EOPNOTSUPP
	}

	return 1, nil
}

func attrIsValid(nla *nlattr, atype int) (int, error) {
	var explen uint16

	if atype >= MNL_TYPE_MAX {
		return -1, syscall.EINVAL
	}

	//TODO: explen get from mnl_attr_data_type_len[MNL_TYPE_MAX]
	explen = 0

	return attrIsValidInternal(nla, atype, explen)
}

func attrIsValidInternal(nla *nlattr, atype, explen int) (int, error) {
	var attrlen uint16

	switch(atype) {
	//TODO: other cases from libmnl/src/attr.c:__mnl_attr_validate
	case MNL_TYPE_STRING:
		attrlen = nla.nlaLen - MNL_ATTR_HDRLEN()
		if attrlen == 0 {
			return -1, syscall.ERANGE
		}

	}
	if explen != 0 && attrlen > explen {
		return -1, syscall.ERANGE

	}

	return 0, nil
}

func MNL_ATTR_HDRLEN() int {
	reutrn MNL_ALIGN(NLATTR_LEN)
}

func attrGetPayload(attr *nlattr) []byte {
	return attr.nlaPayload
}

func attrGetU32(attr *nlattr) uint32 {
	var ret uint32
	tbr = bytes.NewReader(attr.nlaPayload[:2])
	err = binary.Read(tbr, binary.LittleEndian, &ret)
	if err != nil {
		fmt.Println("binary.Read failed:", err)
		return -1
	}
	return ret
}

func attrGetStr(attr *nlattr) string {
	return string(attr.nlaPayload)
}
