#!/bin/bash
# Test cache line behavior with perf for fi_msg_rma alignment

set -e

SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"
FABTEST_BIN="~/libfabric/fabtests/install/bin/fi_rma_pingpong"
DURATION=10  # seconds

echo "=== EFA-Direct RMA Cache Line Alignment Test ==="
echo ""

# Function to run test and collect perf stats
run_test() {
    local label=$1
    local output_file=$2
    
    echo "Running test: $label"
    echo "Starting server on $SERVER..."
    
    # Start server in background with perf
    ssh $SERVER "sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores \
        -o /tmp/perf_server_${output_file}.txt \
        $FABTEST_BIN -p efa -f efa-direct -S 1 -w 0 -I 1 -E" &
    
    SERVER_PID=$!
    sleep 2
    
    echo "Starting client on $CLIENT..."
    
    # Run client with perf
    ssh $CLIENT "sudo perf stat -e cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,L1-dcache-stores \
        -o /tmp/perf_client_${output_file}.txt \
        timeout ${DURATION} $FABTEST_BIN -p efa -f efa-direct -S 1 -w 0 -I 1 -E $SERVER" || true
    
    # Kill server
    ssh $SERVER "pkill -9 fi_rma_pingpong" || true
    wait $SERVER_PID 2>/dev/null || true
    
    # Collect results
    echo "Collecting results..."
    scp $SERVER:/tmp/perf_server_${output_file}.txt ./perf_server_${output_file}.txt
    scp $CLIENT:/tmp/perf_client_${output_file}.txt ./perf_client_${output_file}.txt
    
    echo "Results saved to perf_*_${output_file}.txt"
    echo ""
}

# Test 1: Baseline (no alignment)
echo "=== Test 1: Baseline (no alignment) ==="
run_test "Baseline" "baseline"

# Now we need to modify the code to add alignment
echo ""
echo "=== Modifying code to add alignment ==="
echo "Adding __attribute__((aligned(64))) to fi_msg_rma in prov/efa/src/efa_rma.c"

# Backup original file
cp prov/efa/src/efa_rma.c prov/efa/src/efa_rma.c.backup

# Add alignment attribute (this is a placeholder - need to find exact location)
echo "Manual step required: Add alignment to struct fi_msg_rma declarations"
echo "Example: struct fi_msg_rma msg __attribute__((aligned(64)));"
echo ""
echo "Press Enter when code is modified and rebuilt..."
read

# Test 2: With alignment
echo "=== Test 2: With alignment ==="
run_test "Aligned" "aligned"

# Restore original
echo ""
echo "Restoring original code..."
mv prov/efa/src/efa_rma.c.backup prov/efa/src/efa_rma.c

# Compare results
echo ""
echo "=== Results Comparison ==="
echo ""
echo "Baseline (no alignment):"
echo "Server:"
grep -E "cache-misses|L1-dcache-load-misses" perf_server_baseline.txt || true
echo "Client:"
grep -E "cache-misses|L1-dcache-load-misses" perf_client_baseline.txt || true

echo ""
echo "Aligned:"
echo "Server:"
grep -E "cache-misses|L1-dcache-load-misses" perf_server_aligned.txt || true
echo "Client:"
grep -E "cache-misses|L1-dcache-load-misses" perf_client_aligned.txt || true

echo ""
echo "Full results in perf_*.txt files"
