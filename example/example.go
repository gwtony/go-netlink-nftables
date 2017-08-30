package main
import (
	"fmt"
	"net"
	"bytes"
	//"time"
	"os/exec"
	//"strings"
	nft "github.com/gwtony/nft-go"
)

func check() {
	cmd := exec.Command("nft", "list ruleset")
	//cmd.Stdin = strings.NewReader("some input")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
	    fmt.Println("Error is", err)
	}
	fmt.Printf("All ruleset: %q\n", out.String())
}

func main() {
	ip := net.ParseIP("10.30.128.224").To4()
	err := nft.SetElemAdd("filter", "bh", ip)
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}

	err = nft.SetElemGet("filter", "bh")
	if err != nil {
		fmt.Println(err)
	}

	err = nft.SetElemDelete("filter", "bh", ip)
	if err != nil {
		fmt.Println("work failed:", err)
		return
	}

	//fmt.Println("return is:", string(res))
	//res, err := nft.TableGet("filter")
	//if err != nil {
	//	fmt.Println("work failed:", err)
	//	return
	//}
	//fmt.Println("return is:", string(res))
}
