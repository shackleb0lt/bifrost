#!/bin/bash

prefix="/srv/tftp/"
down_dir="test_down/"
upl_dir="test_up/"
temp_dir="bld/"

# ip_addr="fe80::362e:b7ff:fe18:1ec4 6969"
# ip_addr="192.168.0.188 6969"
ip_addr="127.0.0.1 6969"

file_1="file_1"
file_2="file_2.txt"
file_3="file_3.txt"
file_4="file_4.png"
file_5="file_5.pdf"
file_6="file_6"
file_7="file_7.mp4"

# $ ls -l /srv/tftp/test_down
# total 2148400
# -rw-rw-rw- 1 nobody nogroup        197 Apr 22 07:58 file_1
# -rw-rw-rw- 1 nobody nogroup        512 Apr 22 07:58 file_2.txt
# -rw-rw-rw- 1 nobody nogroup       4516 Apr 22 07:58 file_3.txt
# -rw-rw-rw- 1 nobody nogroup     770888 Apr 22 07:58 file_4.png
# -rw-rw-rw- 1 nobody nogroup   75113906 Apr 22 10:00 file_5.pdf
# -rw-rw-rw- 1 nobody nogroup  400000000 Apr 22 07:58 file_6
# -rw-rw-rw- 1 nobody nogroup 1724042076 Apr 22 10:07 file_7.mp4

# Function to clean up and terminate the background server
cleanup()
{
    trap - EXIT
    echo "Terminating the background server..."
    kill -SIGINT $bg_pid
    wait $bg_pid
}

set -ex

make clean
make debug

sudo rm -f /srv/tftp/test_upload/*
echo ""

sudo -u nobody ./bld/serv_tftp &
bg_pid=$!

sleep 1

if ! kill -0 "$bg_pid" 2>/dev/null; then
    exit 1
else
    echo "Server started successfully with PID: $bg_pid"
fi

trap cleanup ERR
trap cleanup EXIT

counter=1
echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -t -l $temp_dir -r $down_dir$file_1 $ip_addr
./bld/client_tftp -p -t -l $temp_dir$file_1 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_1 $prefix$upl_dir$file_1; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -b 8192 -w 8 -l $temp_dir -r $down_dir$file_1 $ip_addr
./bld/client_tftp -p -b 8192 -w 8 -l $temp_dir$file_1 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_1 $prefix$upl_dir$file_1; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -t -l $temp_dir -r $down_dir$file_2 $ip_addr
./bld/client_tftp -p -t -l $temp_dir$file_2 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_2 $prefix$upl_dir$file_2; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -b 1024 -w 4 -l $temp_dir -r $down_dir$file_2 $ip_addr
./bld/client_tftp -p -b 1024 -w 4 -l $temp_dir$file_2 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_2 $prefix$upl_dir$file_2; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -t -l $temp_dir -r $down_dir$file_3 $ip_addr
./bld/client_tftp -p -t -l $temp_dir$file_3 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_3 $prefix$upl_dir$file_3; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -w 7 -l $temp_dir -r $down_dir$file_3 $ip_addr
./bld/client_tftp -p -w 7 -l $temp_dir$file_3 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_3 $prefix$upl_dir$file_3; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -t -l $temp_dir -r $down_dir$file_4 $ip_addr
./bld/client_tftp -p -t -l $temp_dir$file_4 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_4 $prefix$upl_dir$file_4; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -t -l $temp_dir -r $down_dir$file_5 $ip_addr
./bld/client_tftp -p -t -l $temp_dir$file_5 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_5 $prefix$upl_dir$file_5; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -b 65464 -l $temp_dir -r $down_dir$file_5 $ip_addr
./bld/client_tftp -p -b 65464 -l $temp_dir$file_5 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_5 $prefix$upl_dir$file_5; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -b 1024 -w 64 -l $temp_dir -r $down_dir$file_5 $ip_addr
./bld/client_tftp -p -b 1024 -w 64 -l $temp_dir$file_5 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_5 $prefix$upl_dir$file_5; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

./bld/client_tftp -g -b 64000 -w 32 -l $temp_dir -r $down_dir$file_6 $ip_addr
./bld/client_tftp -p -b 64000 -w 32 -l $temp_dir$file_6 -r $upl_dir $ip_addr

if cmp -s $prefix$down_dir$file_6 $prefix$upl_dir$file_6; then
    echo "Test $counter passed"
else
    echo "Test $counter failed"
    exit 1
fi
((counter++))

echo "-------------------------------------------------------------------------------"

# ./bld/client_tftp -g -b 64000 -w 32 -l $temp_dir -r $down_dir$file_7 $ip_addr
# ./bld/client_tftp -p -b 64000 -w 32 -l $temp_dir$file_7 -r $upl_dir $ip_addr

# if cmp -s $prefix$down_dir$file_7 $prefix$upl_dir$file_7; then
#     echo "Test $counter passed"
# else
#     echo "Test $counter failed"
#     exit 1
# fi
# ((counter++))

# echo "-------------------------------------------------------------------------------"

echo "TFTP test completed!"
