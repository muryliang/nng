package main

import (
    "fmt"
    "time"
    "encoding/binary"
)

var aa = "hehe"
var ch = make(chan struct{}, 1)

func b(c map[string]int) {
    c["hehe"] = 1
    for k := range c {
        fmt.Printf("%s\n", k)
    }
    for k, v := range c {
        fmt.Printf("%s %d\n", k, v)
    }
}

func main() {
    fmt.Println(aa)
    go func() {
        ch <- struct{}{}
    }()
    time.Sleep(time.Millisecond)
    select {
    case <-ch:
    default:
        fmt.Printf("default\n")
    }
    func() {
        fmt.Printf("in func\n")
    }()
    fmt.Printf("done\n")

    cmap := make(map[string]int)
    b(cmap)
    for k, v := range cmap {
        fmt.Printf("map %s=>%d\n", k, v)
    }

    var a uint32 = 0x12345678
    var b uint32 = 0x9abcdef0
    var c uint64 = (uint64(a) << 32) | uint64(b)
    var d []byte = []byte{0x12, 0x34, 0x56, 0x78}
    var e uint64 = 128
    var f []byte = []byte{}
    fmt.Printf("c is %x, %x, %d, %#v, %#v\n", c, binary.BigEndian.Uint32(d), int(e), d[3:4], f[1:1])
    d = append(d, []byte{0x11}...)
    fmt.Printf("d %v\n", d)

}
