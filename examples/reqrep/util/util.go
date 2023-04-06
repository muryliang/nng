package util

import (
    "strings"
    "net"
    "errors"
    "crypto/sha256"
    "math/big"
)

func ConcatString(strs ...string) (string, error) {
    var builder strings.Builder
    for _, str := range strs {
        _, err := builder.WriteString(str)
        if err != nil {
            return "", err
        }
    }
    return builder.String(), nil
}

func GetIntfFromAddr(laddr string) (*net.Interface, error) {
    intfs, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    for _, intf := range intfs {
        addrs, err := intf.Addrs()
        if err != nil {
            return nil, err
        }
        for _, addr := range addrs {
            if strings.Split(addr.String(), "/")[0] == laddr {
                return &intf, nil
            }
        }
    }
    return nil, errors.New("not find intf")
}

// get mac string from input address format xx.xx.xx.xx/mask
func GetMacFromAddr(laddr string) ([]byte, error) {
    intfs, err := net.Interfaces()
    if err != nil {
        return nil, err
    }
    for _, intf := range intfs {
        addrs, err := intf.Addrs()
        if err != nil {
            return nil, err
        }
        for _, addr := range addrs {
            if strings.Split(addr.String(), "/")[0] == laddr {
                return []byte(intf.HardwareAddr), nil
            }
        }
    }
    return nil, errors.New("not find mac")
}

func HashFromBytes(msg []byte, mod int) int {
    hash := sha256.Sum256([]byte(msg))

	// Convert the hash to a big integer
	hashInt := new(big.Int)
	hashInt.SetBytes(hash[:])

	// Define the range you want to map the hash value to
	max := big.NewInt(int64(mod))

	// Map the hash value to the range
	hashInt.Mod(hashInt, max)
    return int(hashInt.Uint64())
}
