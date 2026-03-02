#!/bin/bash
# Run 5 iterations of baseline and aligned tests

PERF="/usr/lib/linux-tools-6.8.0-101/perf"
SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"
FABTEST="~/libfabric/fabtests/install/bin/fi_rma_pingpong"

run_test() {
    local label=$1
    local iter=$2
    
    ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
    sleep 3
    
    ssh $SERVER "$PERF stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses $FABTEST -p efa -f efa-direct -S 1 -w 0 -I 1 -E 2>&1" > /tmp/server_${label}_${iter}.log &
    sleep 5
    
    ssh $CLIENT "$PERF stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses $FABTEST -p efa -f efa-direct -S 1 -w 0 -I 1 -E $SERVER 2>&1" > /tmp/client_${label}_${iter}.log
    wait
    
    echo "Iteration $iter ($label):"
    echo "  Server cache-misses: $(grep cache-misses /tmp/server_${label}_${iter}.log | head -1 | awk '{print $1}')"
    echo "  Client cache-misses: $(grep cache-misses /tmp/client_${label}_${iter}.log | head -1 | awk '{print $1}')"
}

echo "=== Running 5 iterations of ALIGNED test ==="
for i in {1..5}; do
    run_test "aligned" $i
done

echo ""
echo "=== Summary - ALIGNED ==="
echo "Server cache-misses:"
for i in {1..5}; do
    grep cache-misses /tmp/server_aligned_${i}.log | head -1 | awk '{print $1}'
done | awk '{sum+=$1; print $1} END {print "Average:", sum/NR}'

echo ""
echo "Client cache-misses:"
for i in {1..5}; do
    grep cache-misses /tmp/client_aligned_${i}.log | head -1 | awk '{print $1}'
done | awk '{sum+=$1; print $1} END {print "Average:", sum/NR}'

echo ""
echo "=== Reverting to baseline (no alignment) ==="
cd ~/libfabric
mv prov/efa/src/efa_rma.c.backup prov/efa/src/efa_rma.c
make -j32 > /dev/null 2>&1 && make install > /dev/null 2>&1
cd fabtests && make -j32 > /dev/null 2>&1 && make install > /dev/null 2>&1

echo ""
echo "=== Running 5 iterations of BASELINE test ==="
for i in {1..5}; do
    run_test "baseline" $i
done

echo ""
echo "=== Summary - BASELINE ==="
echo "Server cache-misses:"
for i in {1..5}; do
    grep cache-misses /tmp/server_baseline_${i}.log | head -1 | awk '{print $1}'
done | awk '{sum+=$1; print $1} END {print "Average:", sum/NR}'

echo ""
echo "Client cache-misses:"
for i in {1..5}; do
    grep cache-misses /tmp/client_baseline_${i}.log | head -1 | awk '{print $1}'
done | awk '{sum+=$1; print $1} END {print "Average:", sum/NR}'
