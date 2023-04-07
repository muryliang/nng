if [ $# -lt 1 ]; then
    echo need send count
    exit 1
fi
for i in $(seq 1 $1)
do
#echo count $i
./main_c tcp://192.168.122.173:22347 $i
done
