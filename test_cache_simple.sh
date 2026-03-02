#!/bin/bash
# Simple cache line test for fi_msg_rma alignment

SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"

echo "=== Step 1: Run baseline test with perf ==="
echo ""
echo "Starting server with perf..."

# Run server with perf in background
ssh $SERVER "cd ~/libfabric && sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses \
    ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 1 -E 2>&1 | tee /tmp/server_baseline.log" &

SERVER_PID=$!
sleep 3

echo "Starting client with perf..."
ssh $CLIENT "cd ~/libfabric && sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses \
    timeout 10 ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 1 -E $SERVER 2>&1 | tee /tmp/client_baseline.log"

# Kill server
ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Baseline Results ==="
echo "Server:"
ssh $SERVER "grep -A 20 'Performance counter stats' /tmp/server_baseline.log"
echo ""
echo "Client:"
ssh $CLIENT "grep -A 20 'Performance counter stats' /tmp/client_baseline.log"

echo ""
echo "=== Next Steps ==="
echo "1. Modify prov/efa/src/efa_rma.c to add alignment:"
echo "   Change: struct fi_msg_rma msg;"
echo "   To:     struct fi_msg_rma msg __attribute__((aligned(64)));"
echo ""
echo "2. Rebuild: cd ~/libfabric && make -j && make install"
echo ""
echo "3. Run this script again to compare"
