#!/bin/bash
# Measure cache misses only in efa_rma_post_write fast path

LIBFABRIC_SO="$HOME/libfabric/install/lib/libfabric.so.1"
SERVER="p5en-odcr-queue-dy-p5en48xlarge-6"
CLIENT="p5en-odcr-queue-dy-p5en48xlarge-7"

echo "=== Testing Fast Path Cache Misses with eBPF ==="
echo ""

# First, find the symbol address
echo "Finding efa_rma_post_write symbol..."
SYMBOL=$(nm -D $LIBFABRIC_SO | grep efa_rma_post_write | head -1)
if [ -z "$SYMBOL" ]; then
    echo "Symbol not found, trying without -D flag..."
    SYMBOL=$(nm $LIBFABRIC_SO 2>/dev/null | grep efa_rma_post_write | head -1)
fi

if [ -z "$SYMBOL" ]; then
    echo "ERROR: efa_rma_post_write not found in libfabric.so"
    echo "Trying to find any efa_rma functions..."
    nm $LIBFABRIC_SO 2>/dev/null | grep efa_rma | head -10
    exit 1
fi

echo "Found: $SYMBOL"
echo ""

# Create bpftrace script
cat > /tmp/trace_rma.bt << 'EOF'
#!/usr/bin/env bpftrace

uprobe:/home/szegel/libfabric/install/lib/libfabric.so.1:efa_rma_writemsg {
    @start[tid] = nsecs;
    @calls++;
}

uretprobe:/home/szegel/libfabric/install/lib/libfabric.so.1:efa_rma_writemsg {
    if (@start[tid] > 0) {
        @duration_ns = hist(nsecs - @start[tid]);
        delete(@start[tid]);
    }
}

END {
    printf("\n=== RMA Write Path Statistics ===\n");
    printf("Total calls: %d\n", @calls);
    printf("\nDuration histogram (nanoseconds):\n");
    print(@duration_ns);
}
EOF

chmod +x /tmp/trace_rma.bt

echo "Starting eBPF trace on client..."
ssh $CLIENT "sudo /tmp/trace_rma.bt" &
TRACE_PID=$!
sleep 2

echo "Running RMA test (10000 iterations)..."
ssh $SERVER "pkill -9 fi_rma_pingpong" 2>/dev/null || true
sleep 2

ssh $SERVER "~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E" > /dev/null 2>&1 &
sleep 3

ssh $CLIENT "~/libfabric/fabtests/install/bin/fi_rma_pingpong -p efa -f efa-direct -S 1 -w 0 -I 10000 -E $SERVER" > /dev/null 2>&1

wait

echo ""
echo "Test complete!"
