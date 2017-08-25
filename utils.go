package nft

func Merge(arr ...[]byte) []byte {
	tlen := 0
	for _, a := range arr {
		tlen += len(a)
	}
	ret := make([]byte, tlen)
	pos := 0
	for _, a := range arr {
		copy(ret[pos:], a)
		pos += len(a)
	}

	return ret
}
