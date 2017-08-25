package nft

import (
	"fmt"
)

func DebugOut(key string, data []byte) {
	fmt.Printf("Len(%d), %s:", len(data), key)
	for _, i := range data {
		fmt.Printf("%02x ", i)
	}
	fmt.Println()
}
