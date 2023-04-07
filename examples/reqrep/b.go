package main

import "flag"
import "fmt"
import "net"

type arrayFlags []string


func (i *arrayFlags) String() string {
    return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
    *i = append(*i, value)
    return nil
}

var myFlags arrayFlags

func main() {
    flag.Var(&myFlags, "l", "Some description for this param.")
    flag.Parse()
    fmt.Printf("myFlags :%v:\n", myFlags)
    intfs, _ := net.Interfaces()
    for _, intf := range intfs {
        addrs, _ := intf.Addrs()
        fmt.Printf("intf %s, mac %s, addrs %v\n", intf.Name, intf.HardwareAddr.String(), addrs)
    }
//    fmt.Printf("%v\n", addrs)
    var a []byte = []byte{0x1,0x2,0x3,0x4,0x5,0x6}
    c := ([6]byte)(a)
    b := make(map[[6]byte][]byte)
    b[c] = []byte{0x5,0x6}
    fmt.Printf("%#v", b)
}
