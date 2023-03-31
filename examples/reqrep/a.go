package main

import (
    "fmt"
    "time"
)

var aa = "hehe"
var ch = make(chan struct{}, 1)

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
}
