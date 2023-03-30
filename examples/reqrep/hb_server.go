// Copyright 2018 The Mangos Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use file except in compliance with the License.
// You may obtain a copy of the license at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// survey implements a survey example.  server is a surveyor listening
// socket, and clients are dialing respondent sockets.
//
// To use:
//
//   $ go build .
//   $ url=tcp://127.0.0.1:40899
//   $ ./survey server $url server & server=$!
//   $ ./survey client $url client0 & client0=$!
//   $ ./survey client $url client1 & client1=$!
//   $ ./survey client $url client2 & client2=$!
//   $ sleep 5
//   $ kill $server $client0 $client1 $client2
//
package main

import (
	"fmt"
	"os"
	"time"
    "sync"
    "encoding/json"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/respondent"
	"go.nanomsg.org/mangos/v3/protocol/surveyor"

	// register transports
	_ "go.nanomsg.org/mangos/v3/transport/all"
)

const (
    HB_MAX_FAIL = 3
    HB_TIMEOUT = 500
)

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func date() string {
	return time.Now().Format(time.ANSIC)
}

/*
func hash_recalculate():
    pass
*/
/*
// select logic
define map_subnet_onoff(addr_str, bool_on)
define map_subnet_version(addr_str, bool_on) (first valid ver is 1)

func recv_install_xfrm:
    first, all handled local, so no worry unhandled liuliang
    push config into redis hset1(key as sub ip pair?)
    push route config into another map hset2, index by one ip(we only have one, maybe 2?)
    check hset and use ip as index check hset2, if all good, we can do install
    notify puller routine:

func puller routine:
    pop from list
    calculate which one to handle
    send to all
    according to map_subnet_onoff, select which to route, add into xdp
*/
/*
// distribute logic
*/
/*
// heartbeat logic
define map_subnet_onoff(addr_str, bool_on)
define map_subnet_fail(addr_str, fail_cnt)
def total_cnt = len(map_subent_fail)
loop:
    def map_test(addr_str, off)
    def recv_cnt = 0
    send_survey
    loop: (set timeout as loop_interval)
        recv with addr_str
        if map_test[addr_str] == off:
            map_test[addr_str] = on
            recv_cnt += 1
            if recv_cnt == total_cnt:
                break_loop
        if recv_cnt == total_cnt:
            sleep(loop_interval)
        else
            map_lock()
            foreach(map_test):
                if map_test[addr_str] == off:
                    map_subnet_fail[addr_str] += 1
                    if map_subnet_fail[addr_str] >= MAX_FAIL:
                        map_subnet_onoff[addr_str] = off
                        changed = 1
                else if map_test[addr_str] == on:
                    map_subnet_fail[addr_str] = 0
                    if map_subnet_onoff[addr_str] == off
                        map_subnet_onoff[addr_str] = on
                        changed = 1
            map_unlock()
            if changed == 1
                trigger hash recalculate()
            // if timeout, we already sleeped that time, continue with out sleep

*/
func server(url string) {
	var sock mangos.Socket
	var err error
	var msg []byte
    var hb_lock sync.Mutex
    hb_map_fail := map[string]int {
        "c1" : 0,
        "c2" : 0,
        "c3" : 0,
    }
    hb_map_onoff := map[string]bool {
        "c1" : false,
        "c2" : false,
        "c3" : false,
    }

    total_cnt := len(hb_map_onoff)
	if sock, err = surveyor.NewSocket(); err != nil {
		die("can't get new surveyor socket: %s", err)
	}
	if err = sock.Listen(url); err != nil {
		die("can't listen on surveyor socket: %s", err.Error())
	}
	err = sock.SetOption(mangos.OptionSurveyTime, time.Millisecond * HB_TIMEOUT)
	if err != nil {
		die("SetOption(): %s", err.Error())
	}
    i := 0
	for {
        tmp_map := map[string]bool {
            "c1" : false,
            "c2" : false,
            "c3" : false,
        }
        recv_cnt := 0
        changed := false

        i++
        fmt.Printf("\nserver: sending hb %d\n", i)
        if err = sock.Send([]byte("hb")); err != nil {
            die("Failed sending survey: %s", err.Error())
        }
        // currently use this, or we may use client send
        // pair mode is ok, just client send enough
        for {
            if msg, err = sock.Recv(); err != nil {
                fmt.Println("get err ", err);
                break
            }
            from_addr := string(msg)
            mapval, ok := tmp_map[from_addr]
            if !ok {
                fmt.Printf("get wrong key %v\n", msg)
            } else {
                if !mapval {
                    tmp_map[from_addr] = true
                    recv_cnt ++
                    if recv_cnt == total_cnt {
                        break
                    }
                }
            }
        }

        hb_lock.Lock()
        for addr, onoff := range tmp_map {
            if !onoff {
                hb_map_fail[addr] += 1
                fmt.Printf("%s failed\n", addr)
                if hb_map_fail[addr] == HB_MAX_FAIL { // when > MAX, already false, not do it
                    fmt.Printf("%s timeout max, set off\n", addr)
                    hb_map_onoff[addr] = false
                    changed = true
                }
            } else {
                hb_map_fail[addr] = 0
                if hb_map_onoff[addr] == false {
                    fmt.Printf("%s recovered, set on\n", addr)
                    hb_map_onoff[addr] = true
                    changed = true
                }
            }
        }
        hb_lock.Unlock()
        
        if changed {
            fmt.Printf("we changed\n")
        }
        res, err := json.MarshalIndent(hb_map_onoff, "", " ")
        if err != nil {
            fmt.Println("some error json", err)
        }
        fmt.Println(string(res))
        if recv_cnt == total_cnt {
            time.Sleep(time.Millisecond * HB_TIMEOUT)
        }
	}
}

func client(url string, name string) {
	var sock mangos.Socket
	var err error
	var msg []byte

	if sock, err = respondent.NewSocket(); err != nil {
		die("can't get new respondent socket: %s", err.Error())
	}
	err = sock.SetOption(mangos.OptionDialAsynch, true)
	if err != nil {
		die("SetOption(): %s", err.Error())
	}
	if err = sock.Dial(url); err != nil {
		die("can't dial on respondent socket: %s", err.Error())
	}
	for {
        fmt.Println("receiving...")
		if msg, err = sock.Recv(); err != nil {
			die("Cannot recv: %s", err.Error())
		}
		fmt.Printf("client(%s): received \"%s\" survey request\n",
			name, string(msg))

		fmt.Printf("client(%s): responding hb\n", name)
		if err = sock.Send([]byte(name)); err != nil {
			die("Cannot send: %s", err.Error())
		}
	}
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "server" {
		server(os.Args[2])
		os.Exit(0)
	}
	if len(os.Args) > 3 && os.Args[1] == "client" {
		client(os.Args[2], os.Args[3])
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "Usage: survey server|client <URL> <ARG>\n")
	os.Exit(1)
}
