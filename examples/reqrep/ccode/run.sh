if [ $# -lt 2 ]; then
    echo need send count range
    exit 1
fi

if [ $# -ge 2 ]; then
from=$1
to=$2
fi

del=0

if [ $# -gt 2 ]; then
del=1
fi

for i in $(seq $from $to)
do
#echo count $i
#./main_c tcp://192.168.122.173:22347 $i
if [ $del -eq 0 ]; then
./main_c tcp://192.168.122.173:22347 $i 192.168.122.$i 192.168.122.1 192.168.122.173 192.168.122.1
else
./main_c tcp://192.168.122.173:22347 $i
fi
done
