if [ $# -lt 5 ]; then
    echo "need [l(local)|r(remote)] spi local_subnet remote_subnet [delete]"
    exit 1
fi

lorr=$1
spi=$2
lnet=$3
rnet=$4
del=$5

if [ $lorr == "l" ]
then
    tmplsrc=172.16.1.50
    tmpldst=172.16.3.21
else
    tmplsrc=172.16.3.21
    tmpldst=172.16.1.50
fi
set -x
./main_c tcp://172.16.1.51:22347 $spi 192.168.${lnet}.0/24 192.168.$rnet.0/24 $tmplsrc $tmpldst $del
