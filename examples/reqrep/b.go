package main

import "flag"
import "fmt"

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
}
