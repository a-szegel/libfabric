#!/bin/bash
# Install perf and run cache alignment test

SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"

echo "=== Installing perf on both nodes ==="
ssh $SERVER "sudo yum install -y perf || sudo apt-get install -y linux-tools-generic linux-tools-\$(uname -r)"
ssh $CLIENT "sudo yum install -y perf || sudo apt-get install -y linux-tools-generic linux-tools-\$(uname -r)"

echo ""
echo "=== Running baseline test ==="
echo "Starting server..."

# Run server with perf
ssh $SERVER "cd ~/libfabric && sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,instructions,cycles \
    ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 1 -E > /tmp/server_out.log 2>&1" &

SERVER_PID=$!
sleep 3

echo "Starting client..."
ssh $CLIENT "cd ~/libfabric && sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,instructions,cycles \
    timeout 10 ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 1 -E $SERVER > /tmp/client_out.log 2>&1"

CLIENT_EXIT=$?

# Kill server
ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Baseline Results ==="
echo ""
echo "Server perf stats:"
ssh $SERVER "cat /tmp/server_out.log | grep -A 30 'Performance counter stats'"
echo ""
echo "Client perf stats:"
ssh $CLIENT "cat /tmp/client_out.log | grep -A 30 'Performance counter stats'"

# Save results
ssh $SERVER "cat /tmp/server_out.log" > ~/libfabric/perf_server_baseline.txt
ssh $CLIENT "cat /tmp/client_out.log" > ~/libfabric/perf_client_baseline.txt

echo ""
echo "Results saved to:"
echo "  ~/libfabric/perf_server_baseline.txt"
echo "  ~/libfabric/perf_client_baseline.txt"
