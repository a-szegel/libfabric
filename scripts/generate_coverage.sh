#!/bin/bash
# Generate code coverage report for EFA provider
# Usage: ./scripts/generate_coverage.sh [output_dir]

set -e

OUTPUT_DIR="${1:-coverage}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=== Generating EFA Code Coverage Report ==="

# Capture coverage data
echo "Capturing coverage data..."
lcov --capture \
     --directory "$ROOT_DIR" \
     --output-file "$OUTPUT_DIR/coverage.info" \
     --rc branch_coverage=1 \
     --ignore-errors source,gcov

# Filter to relevant files
echo "Filtering coverage data..."
lcov --extract "$OUTPUT_DIR/coverage.info" \
     "*/src/*" "*/include/*" "*/prov/util/*" "*/prov/efa/src/*" \
     --output-file "$OUTPUT_DIR/coverage_filtered.info" \
     --rc branch_coverage=1

# Generate HTML report
echo "Generating HTML report..."
genhtml "$OUTPUT_DIR/coverage_filtered.info" \
        --output-directory "$OUTPUT_DIR/html" \
        --title "EFA Provider Code Coverage" \
        --legend \
        --branch-coverage \
        --rc branch_coverage=1

# Show summary
echo ""
echo "=== Coverage Summary ==="
lcov --summary "$OUTPUT_DIR/coverage_filtered.info" --rc branch_coverage=1

echo ""
echo "Report generated: $OUTPUT_DIR/html/index.html"
