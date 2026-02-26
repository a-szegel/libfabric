#!/bin/bash
# Helper script to track and convert cmocka tests to gtest

TEST_DIR="/home/szegel/libfabric/prov/efa/test"
STATUS_FILE="$TEST_DIR/MIGRATION_STATUS.md"

echo "=== EFA Test Migration Helper ==="
echo

# Count total tests
total_tests=$(grep -h "^void test_" $TEST_DIR/efa_unit_test_*.c 2>/dev/null | wc -l)
echo "Total test functions to convert: $total_tests"
echo

# Show breakdown by file
echo "Tests per file:"
for f in $TEST_DIR/efa_unit_test_*.c; do
    if [ -f "$f" ]; then
        basename_f=$(basename "$f")
        count=$(grep -c "^void test_" "$f" 2>/dev/null || echo 0)
        if [ "$count" -gt 0 ]; then
            printf "  %-40s %3d tests\n" "$basename_f" "$count"
        fi
    fi
done | sort -t: -k2 -rn

echo
echo "Strategy: Convert 374 tests across 21 files"
echo "Current: 5 basic mock tests passing"
echo "Next: Add real provider integration"
