package nft

import (
	"fmt"
	"bytes"
	"encoding/binary"
)

const (
	DATA_NONE = iota
	DATA_VALUE
	DATA_VERDICT
	DATA_CHAIN
)

//Not use union
type NftDatareg struct {
	val []uint32 //size is NFT_DATA_VALUE_MAXLEN/sizeof(uint32_t), NFT_DATA_VALUE_MAXLEN is 64
	vlen uint32
	verdict int
	chain string
}

func nftnlParseData(data *NftDatareg, attr *nlattr) int {
	fmt.Println("in nftnlDataParse")
	body := attr.nlaPayload
	blen := len(body)
	if blen == 0 {
		return -1
	}
	if blen > 64 { //NFT_DATA_VALUE_MAXLEN
		return -1
	}
	if (blen % 4) != 0 {
		fmt.Println("len invalid")
		return -1
	}
	data.val = make([]uint32, 0, 16) //16: 64/sizeof(uint32)

	//DebugOut(body)

	pos := 0
	var val uint32
	for {
		if pos == blen {
			break
		}
		tbr := bytes.NewReader(body[pos:pos + 4])
		err := binary.Read(tbr, binary.LittleEndian, &val)
		if err != nil {
			fmt.Println("binary read error:", err)
		}
		fmt.Println("val is", val)
		data.val = append(data.val, val)
		pos += 4
	}
	data.vlen = uint32(blen)

	return 0
}

//Return data, atype, ret
func NftnlParseData(data *NftDatareg, attr *nlattr) (int, int) {
	fmt.Println("in NftnlDataParse")
	ret := 0
	am := make(attrmap, NFTA_DATA_MAX+1)
	rtype := 0

	ret, err := attrParseNested(attr, NftnlDataParseCb, am)
	if err != nil {
		return rtype, -1
	}

	if i, ok := am[NFTA_DATA_VALUE]; ok {
		fmt.Println("in NftnlParseData rtype is DATA_VALUE")
		rtype = DATA_VALUE

		ret = nftnlParseData(data, i)
		if ret < 0 {
			return rtype, ret
		}
	}

	if i, ok := am[NFTA_DATA_VERDICT]; ok {
		fmt.Println("in NftnlParseData call parse verdict")
		rtype, ret = NftnlParseVerdict(data, i)
	}

	return rtype, ret
}

func NftnlDataParseCb(attr *nlattr, am attrmap) int {
	fmt.Println("in NftnlDataParseCb")
	atype := attrGetType(attr)
	if _, err := attrTypeIsValid(attr, NFTA_DATA_MAX); err != nil {
		fmt.Println("in NftnlDataParseCb")
		return MNL_CB_OK
	}
	switch(atype) {
	case NFTA_DATA_VALUE:
		if _, err := attrIsValid(attr, MNL_TYPE_BINARY); err != nil {
			//TODO: exit, return what
			fmt.Println("in NftnlDataParseCb type is NFTA_DATA_VALUE")
			return -1
		}
	case NFTA_DATA_VERDICT:
		if _, err := attrIsValid(attr, MNL_TYPE_NESTED); err != nil {
			//TODO: exit, return what
			fmt.Println("in NftnlDataParseCb type is NFTA_DATA_VERDICT")
			return -1
		}
	}

	am[atype] = attr
	return MNL_CB_OK
}

func NftnlParseVerdict(data *NftDatareg, attr *nlattr) (int, int) {
	//TODO: libnftnl/src/expr/data_reg.c:nftnl_parse_verdict
	fmt.Println("in NftnlParseVerdict but do nothing")
	return 0, 0
}
