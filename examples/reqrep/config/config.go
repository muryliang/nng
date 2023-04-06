package config

const (
    OP_DUMB    uint32 = iota
    OP_ADD_SA
    OP_DEL_SA 
    OP_STATUS
)

var Gmap = map[uint32]string {
    OP_ADD_SA : "add_sa",
    OP_DEL_SA : "del_sa",
}

type Config struct {
    Op      uint32
    Data    []byte
}

type VerCfg struct {
    Ver int64
    Cfg Config
}

