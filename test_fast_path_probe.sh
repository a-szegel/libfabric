#!/bin/bash
# Measure fast path with perf probe

SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"
PERF="/usr/lib/linux-tools-6.8.0-101/perf"
LIBFABRIC="$HOME/libfabric/install/lib/libfabric.so.1"

echo "=== Measuring Fast Path with perf probe ==="
echo ""

# Add probes on client
echo "Adding probes to efa_rma_writemsg..."
ssh $CLIENT "sudo $PERF probe -x $LIBFABRIC -d 'efa_rma_*' 2>/dev/null || true"
ssh $CLIENT "sudo $PERF probe -x $LIBFABRIC --add 'efa_rma_writemsg' 2>&1 | head -5"

echo ""
echo "Running test with 10000 iterations..."
ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
sleep 2

# Start server
ssh $SERVER "~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E" > /dev/null 2>&1 &
sleep 3

# Run client with perf record on the probe
ssh $CLIENT "cd /tmp && sudo $PERF record -e cache-misses,L1-dcache-load-misses -e probe:efa_rma_writemsg -g --call-graph dwarf -o perf_fastpath.data ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E $SERVER" > /dev/null 2>&1

wait

echo ""
echo "=== Results ==="
ssh $CLIENT "cd /tmp && sudo $PERF report -i perf_fastpath.data --stdio --no-children 2>/dev/null | head -100"

echo ""
echo "Cleaning up probes..."
ssh $CLIENT "sudo $PERF probe -d 'efa_rma_*' 2>/dev/null || true"
