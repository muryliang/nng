set -x
#gcc main.c /opt/nng/lib64/libnng.a -o main -I /opt/nng/include/ -lpthread
gcc main_c.c slb.pb-c.c /opt/nng/lib64/libnng.a -o main_c -I /opt/nng/include/ -lpthread -lprotobuf-c -g
