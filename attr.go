package nft
import (
	"fmt"
	//"errors"
	"bytes"
	"encoding/binary"
	//"unsafe"
	"syscall"
)

func attrz(name []byte, attrType int) []byte {
	nlen := len(name)
	attr := make([]byte, MNL_ALIGN(nlen + 1 + 4)) //4 is attr hdr len

	alen := uint16(nlen + 1 + 4)
	buf := bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, alen)
	//fmt.Printf("attr length len(%d): %02x, %02x\n", b_buf.Len(), b_buf.Bytes()[0], b_buf.Bytes()[1])
	fmt.Println()
	copy(attr[0:2], buf.Bytes())

	atype := uint16(attrType)
	buf = bytes.NewBuffer([]byte{})
	binary.Write(buf, binary.LittleEndian, atype)
	//fmt.Printf("attr type: %02x, %02x\n", b_buf.Bytes()[0], b_buf.Bytes()[1])
	copy(attr[2:4], buf.Bytes())
	copy(attr[4:], name)

	//For debug
	//fmt.Printf("len(%d), name(%s): ", len(attr), string(name))
	//for _, ai := range attr {
	//	fmt.Printf("%02x ", ai)
	//}
	//fmt.Println("")

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

	//For debug
	//fmt.Printf("len(%d), name(%s): ", len(attr), string(name))
	//for _, ai := range attr {
	//	fmt.Printf("%02x ", ai)
	//}
	//fmt.Println("")

	return attr
}

func elem_attr(name []byte) []byte { //TODO: change
	datav := attr(name, NFTA_DATA_VALUE)
	keyv := attr(datav, syscall.NLA_F_NESTED | NFTA_SET_ELEM_KEY)
	idxv := attr(keyv, syscall.NLA_F_NESTED | 1) //index begin from 1
	elem := attr(idxv, NFTA_SET_ELEM_LIST_ELEMENTS | syscall.NLA_F_NESTED)
	return elem
}

