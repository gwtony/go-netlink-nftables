package nft

import (
	"fmt"
	"syscall"
)

func TableGet(name string) ([]byte, error) {
	s, lsa, err := NLSocket()
	if err != nil {
		fmt.Println("create nl socket failed")
		return nil, err
	}
	defer NLClose(s)

	nr := newNetlinkRequest(NFT_MSG_GETTABLE, syscall.NLM_F_ACK)

	table := attrz([]byte(name), NFTA_TABLE_NAME)
	wb := nr.Serialize(table)

	//debug
	//fmt.Println("all data len is", len(wb))
	//fmt.Printf("all data to send: ")
	//for _, i := range wb {
	//	fmt.Printf("%02x ", i)
	//}
	//fmt.Println()

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
