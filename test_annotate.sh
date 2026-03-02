#!/bin/bash
# Use perf annotate to see instruction-level cache misses

SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"
PERF="/usr/lib/linux-tools-6.8.0-101/perf"

echo "=== Instruction-Level Cache Miss Analysis ==="
echo ""

ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
sleep 2

echo "Running test with perf record (10000 iterations)..."

# Start server
ssh $SERVER "~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E" &
sleep 3

# Client with precise event sampling
ssh $CLIENT "cd /tmp && $PERF record -e cache-misses:pp -g --call-graph dwarf ~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E $SERVER" > /dev/null 2>&1

wait

echo ""
echo "=== Top Functions by Cache Misses ==="
ssh $CLIENT "cd /tmp && $PERF report -i perf.data --stdio --no-children --sort symbol 2>/dev/null | grep -E 'libfabric|fi_rma' | head -20"

echo ""
echo "=== Annotated efa_rma_writemsg (if available) ==="
ssh $CLIENT "cd /tmp && $PERF annotate -i perf.data --stdio efa_rma_writemsg 2>/dev/null | head -50"

echo ""
echo "Done! Full report available on $CLIENT:/tmp/perf.data"
