#!/bin/bash
# Quick build and test script for GoogleTest conversion

set -e

echo "=== EFA GoogleTest Build and Test ==="
echo

cd /home/szegel/libfabric

echo "Step 1: Running autogen.sh..."
./autogen.sh > /dev/null 2>&1

echo "Step 2: Configuring with GoogleTest..."
./configure --enable-gtest --quiet

echo "Step 3: Building..."
make -j$(nproc) > /dev/null 2>&1

echo "Step 4: Running GoogleTest tests..."
echo

# Run each test
for test in prov/efa/test/efa_unit_test_device_test \
            prov/efa/test/efa_unit_test_fork_support_test \
            prov/efa/test/efa_unit_test_send_test; do
    if [ -f "$test" ]; then
        echo "Running $test..."
        ./$test
        echo
    else
        echo "WARNING: $test not built"
    fi
done

echo "=== All tests completed ==="
