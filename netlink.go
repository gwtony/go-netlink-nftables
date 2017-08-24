package nft
import (
	"fmt"
	//"errors"
	"bytes"
	"encoding/binary"
	//"unsafe"
	"syscall"
)
func NLSocket() (fd int, lsa *syscall.SockaddrNetlink, err error) {
	//var errno int
	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_NETFILTER)
	if err != nil {
		fmt.Println("socket failed")
		return -1, nil, err
	}
	//defer syscall.Close(s)
	lsa = &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err = syscall.Bind(s, lsa); err != nil {
		syscall.Close(s)
		fmt.Println("bind failed")
		return -1, nil, err
	}

	return s, lsa, nil
}

func NLClose(fd int) {
	syscall.Close(fd)
}

func NLSend(fd int, data []byte, flag int, lsa *syscall.SockaddrNetlink) error {
	if err := syscall.Sendto(fd, data, 0, lsa); err != nil {
		fmt.Println("sendto failed")
		return err
	}
	return nil
}

func NLRecv(fd int) ([]byte, error) {
	var errno int
	var tab []byte
	rbNew := make([]byte, syscall.Getpagesize())

done:
	ret := 0
	for {
		fmt.Println("to recv")
		rb := rbNew
		nr, _, err := syscall.Recvfrom(fd, rb, 0)
		if err != nil {
			fmt.Println("recv from failed")
			return nil, err
		}
		if nr == 0 {
			fmt.Println("recv done")
			break
		}
		if nr < syscall.NLMSG_HDRLEN {
			fmt.Println("not header len")
			return nil, syscall.EINVAL
		}
		//fmt.Println("recv %d data", nr)
		rb = rb[:nr]
		tab = append(tab, rb...)
		msgs, err := syscall.ParseNetlinkMessage(rb)
		if err != nil {
			fmt.Println("parse message failed")
			return nil, err
		}
		fmt.Println("recv msgs len is %d", len(msgs))
		for _, m := range msgs {
			fmt.Println("header is", m.Header.Type)
			lsa, err := syscall.Getsockname(fd)
			if err != nil {
				fmt.Println("get sockname failed")
				return nil, err
			}
			switch lsa.(type) {
			//switch v := lsa.(type) {
			case *syscall.SockaddrNetlink:
				fmt.Printf("seq is %d, pid is %d\n", m.Header.Seq, m.Header.Pid)
				fmt.Println(m)
				//if m.Header.Seq != 1 || m.Header.Pid != v.Pid {
				//	fmt.Println("seq or pid not match")
				//	return nil, syscall.EINVAL
				//}
			default:
				fmt.Println("not sockaddr netlink")
				return nil, syscall.EINVAL
			}
			if m.Header.Type == syscall.NLMSG_DONE {
				fmt.Println("nlmsg done")
				goto done
			}
			if m.Header.Type == syscall.NLMSG_ERROR {
				ret, errno = cberror(m)
				if ret <= 0 {
					goto end
				}
			}
		}
	}
end:
	if ret < 0 {
		fmt.Println("errno is", syscall.Errno(errno))
		return nil, syscall.Errno(errno)
	}

	return tab, nil
}

func cberror(nm syscall.NetlinkMessage) (int, int) {
	var nlme syscall.NlMsgerr
	//TODO: check header len
	buf := bytes.NewReader(nm.Data)
	err := binary.Read(buf, binary.LittleEndian, &nlme.Error)
	if err != nil {
		fmt.Println("parse nlmsgerr failed")
		return MNL_CB_ERROR, 0
	}
	//TODO: parse others in nlme
	errno := int32(0)
	if nlme.Error < 0 {
		fmt.Println(nlme.Error)
		errno = -nlme.Error //parse netfilter error
	} else {
		fmt.Println(nlme.Error)
		errno = nlme.Error
	}
	fmt.Printf("error is %x\n", int(errno))
	if nlme.Error == 0 {
		return MNL_CB_STOP, int(errno)
	} else {
		return MNL_CB_ERROR, int(errno)
	}
}

