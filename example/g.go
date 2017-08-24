package main
import (
	"fmt"
	nft "github.com/gwtony/nft-go"
)

func main() {
	//res, err := nft.SetElemAdd()
	//if err != nil {
	//	fmt.Println("work failed:", err)
	//	return
	//}
	//fmt.Println("return is:", string(res))

	res, err := nft.TableGet("filter")
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}
	fmt.Println("return is:", string(res))
}
