package main
import (
	"fmt"
	"bytes"
	"os/exec"
	nft "github.com/gwtony/nft-go"
)

func check() {
	cmd := exec.Command("nft", "list ruleset")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
	    fmt.Println("Error is", err)
	}
	fmt.Printf("in all caps: %q\n", out.String())
}

func main() {
	err := nft.SetElemAdd()
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}
	check()

	err = nft.SetElemDelete()
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}
	check()
	//fmt.Println("return is:", string(res))
	//res, err := nft.TableGet("filter")
	//if err != nil {
	//	fmt.Println("work failed:", err)
	//	return
	//}
	//fmt.Println("return is:", string(res))
}
