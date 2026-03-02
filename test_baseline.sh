#!/bin/bash
# Cache alignment test for fi_msg_rma

PERF="/usr/lib/linux-tools-6.8.0-101/perf"
SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"
FABTEST="~/libfabric/fabtests/install/bin/fi_rma_pingpong"

echo "=== Baseline Test (No Alignment) ==="
echo ""

ssh $SERVER "$PERF stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses $FABTEST -p efa -f efa-direct -S 1 -w 0 -I 1 -E" > /tmp/server_baseline.log 2>&1 &
sleep 2
ssh $CLIENT "$PERF stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses $FABTEST -p efa -f efa-direct -S 1 -w 0 -I 1 -E $SERVER" > /tmp/client_baseline.log 2>&1
wait

echo "Server baseline:"
grep -A 10 "Performance counter stats" /tmp/server_baseline.log
echo ""
echo "Client baseline:"
grep -A 10 "Performance counter stats" /tmp/client_baseline.log

echo ""
echo "=== Baseline Results Summary ==="
echo "Server cache misses: $(grep cache-misses /tmp/server_baseline.log | head -1 | awk '{print $1}')"
echo "Server L1-dcache-load-misses: $(grep L1-dcache-load-misses /tmp/server_baseline.log | head -1 | awk '{print $1}')"
echo "Client cache misses: $(grep cache-misses /tmp/client_baseline.log | head -1 | awk '{print $1}')"
echo "Client L1-dcache-load-misses: $(grep L1-dcache-load-misses /tmp/client_baseline.log | head -1 | awk '{print $1}')"

cp /tmp/server_baseline.log ~/libfabric/perf_server_baseline.txt
cp /tmp/client_baseline.log ~/libfabric/perf_client_baseline.txt

echo ""
echo "Results saved to ~/libfabric/perf_*_baseline.txt"
