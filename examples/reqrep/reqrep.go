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

// reqprep implements a request/reply example.  node0 is a listening
// rep socket, and node1 is a dialing req socket.
//
// To use:
//
//   $ go build .
//   $ url=tcp://127.0.0.1:40899
//   $ ./reqrep node0 $url & node0=$! && sleep 1
//   $ ./reqrep node1 $url
//   $ kill $node0
//
package main

import (
	"fmt"
	"os"
	"time"
    "net"
    "encoding/binary"
    "encoding/hex"
    "bytes"

	"go.nanomsg.org/mangos/v3"
	"go.nanomsg.org/mangos/v3/protocol/rep"
	"go.nanomsg.org/mangos/v3/protocol/req"

	// register transports
	_ "go.nanomsg.org/mangos/v3/transport/all"
    "google.golang.org/protobuf/proto"
)

const (
    ADD_SA uint32 = iota
    DEL_SA 
    STATUS
)

const (
    ST_OK int64 = iota
    ST_FAIL

)

var gmap = map[uint32]string {
    ADD_SA : "add_sa",
    DEL_SA : "del_sa",
}

func die(format string, v ...interface{}) {
	fmt.Fprintln(os.Stderr, fmt.Sprintf(format, v...))
	os.Exit(1)
}

func date() string {
	return time.Now().Format(time.ANSIC)
}

func node0(url string) {
	var sock mangos.Socket
	var err error
	var msg []byte
	if sock, err = rep.NewSocket(); err != nil {
		die("can't get new rep socket: %s", err)
	}
	if err = sock.Listen(url); err != nil {
		die("can't listen on rep socket: %s", err.Error())
	}
    i := 0
	for {
		// Could also use sock.RecvMsg to get header
        i++
		msg, err = sock.Recv()
		if err != nil {
			die("cannot receive on rep socket: %s", err.Error())
		}
        fmt.Printf("get msg %s\n", hex.EncodeToString(msg))
        sareq := &AddSaReq{}
        msglen := int(binary.BigEndian.Uint32(msg[:4]))
        if msglen != len(msg) {
            die("msg len not correct %x %d", msglen, len(msg))
        }
        op := binary.BigEndian.Uint32(msg[4:8])
        fmt.Printf("op is %s\n", gmap[op])
        err := proto.Unmarshal(msg[8:], sareq)
        if err != nil {
            die("can not parse received data")
        }
        srcip := net.IP(sareq.GetHostSrc())
        dstip := net.IP(sareq.GetHostDst())
        fmt.Printf("NODE0: RECEIVED size %d, src:%s, dst:%s, spi:%x\n", len(msg), srcip.String(), dstip.String(), sareq.GetSpi())

        resp := &StatusResp{}
        resp.Status = ST_FAIL

        buf := new(bytes.Buffer)
        binary.Write(buf, binary.BigEndian, int32(proto.Size(resp) + 8))
        binary.Write(buf, binary.BigEndian, int32(STATUS))
        respmsg, err := proto.Marshal(resp)
        if err != nil {
            die("can't marshal : %s", err.Error())
        }
        fmt.Printf("before marshal buffer len is %d, msglen %d, protolen %d\n", buf.Len(), len(respmsg), proto.Size(resp))
        _, err = buf.Write(respmsg)
        if err != nil {
            die("can't buf write : %s", err.Error())
        }
//        fmt.Printf("%d NODE0: SENDING DATE %s\n", i, d)
        err = sock.Send(buf.Bytes())
        if err != nil {
            die("can't send reply: %s", err.Error())
        }
	}
}

func node1(url string) {
	var sock mangos.Socket
	var err error
	var msg []byte

	if sock, err = req.NewSocket(); err != nil {
		die("can't get new req socket: %s", err.Error())
	}
	if err = sock.Dial(url); err != nil {
		die("can't dial on req socket: %s", err.Error())
	}
	fmt.Printf("NODE1: SENDING DATE REQUEST %s\n", "DATE")
	if err = sock.Send([]byte("DATE")); err != nil {
		die("can't send message on push socket: %s", err.Error())
	}
	if msg, err = sock.Recv(); err != nil {
		die("can't receive date: %s", err.Error())
	}
	fmt.Printf("NODE1: RECEIVED DATE %s\n", string(msg))
	sock.Close()
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "node0" {
		node0(os.Args[2])
		os.Exit(0)
	}
	if len(os.Args) > 2 && os.Args[1] == "node1" {
		node1(os.Args[2])
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "Usage: reqrep node0|node1 <URL>\n")
	os.Exit(1)
}
