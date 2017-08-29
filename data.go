package nft

import (
	"fmt"
	"encoding/binary"
)

//Not use union
type NftDatareg struct {
	val [16]uint32 //size is NFT_DATA_VALUE_MAXLEN/sizeof(uint32_t), NFT_DATA_VALUE_MAXLEN is 64
	vlen uint32
	verdict int
	chain string
}

func nftnlParseData(data *NftDatareg, attr *nlattr) int {
	orig := attr.nlaPayload
	dlen := len(orig)
	if dlen == 0 {
		return -1
	}
	if dlen > 64 { //NFT_DATA_VALUE_MAXLEN
		return -1
	}

	data.val = make([]uint32, 0, dlen/4) //4 is sizeof(uint32)
	//TODO: memcpy(data->val, orig, data_len);
	data.val[0] = 0
	data.vlen = dlen
}

//Return data, atype, ret
func NftnlParseData(data *NftDatareg, attr *nlattr, atype int) (int, int) {
	ret := 0
	am := make(attrmap, NFTA_DATA_MAX+1)
	rtype := 0

	ret, err := attrParseNested(attr, NftnlDataParseCb, am)
	if err != nil {
		return rtype, -1
	}

	if i, ok := am[NFTA_DATA_VALUE]; ok {
		if atype != 0 {
			rtype = DATA_VALUE
		}
		ret = nftnlParseData(data, i)
		if ret < 0 {
			return rtype, ret
		}
	}

	if i, ok := am[NFTA_DATA_VERDICT]; ok {
		rtype, ret = NftnlParseVerdict(data, i)
	}

	return rtype, ret
}

func NftnlDataParseCb(attr *nlattr, am attrmap) int {
	atype := attrGetType(attr)
	if ret, err := attrTypeIsValid(attr, NFTA_DATA_MAX); err != nil {
		return MNL_CB_OK
	}
	switch(atype) {
	case NFTA_DATA_VALUE:
		if ret, err := attrIsValid(attr, MNL_TYPE_BINARY); err != nil {
			//TODO: exit, return what
			return -1
		}
	case NFTA_DATA_VERDICT:
		if ret, err := attrIsValid(attr, MNL_TYPE_NESTED); err != nil {
			//TODO: exit, return what
			return -1
		}
	}

	am[atype] = attr
	return MNL_CB_OK
}

func NftnlParseVerdict(data *NftDatareg, attr *nlattr) (int, int) {
	//TODO: libnftnl/src/expr/data_reg.c:nftnl_parse_verdict
	return 0, 0
}
