# Code Coverage for EFA Provider

## Quick Start

```bash
# 1. Configure and build with coverage
./configure --enable-efa --enable-efa-unit-test=/path/to/cmocka \
            CFLAGS="-O0 -g --coverage" LDFLAGS="--coverage"
make -j$(nproc)

# 2. Run unit tests
make check

# 3. Generate coverage report
make coverage
```

View report: `firefox coverage/html/index.html`

## Requirements

- GCC with gcov support
- lcov (`apt-get install lcov` or `yum install lcov`)
- CMocka library (for unit tests)
- EFA device (for running tests)

## Make Targets

- `make coverage` - Generate coverage report
- `make coverage-clean` - Clean coverage data

## Manual Usage

```bash
# Generate report manually
./scripts/generate_coverage.sh [output_dir]

# Clean coverage data
find . -name "*.gcda" -delete
rm -rf coverage/
```

## Coverage Scope

Tracks coverage for:
- `src/` - Core libfabric
- `include/` - Headers  
- `prov/util/` - Utility provider
- `prov/efa/src/` - EFA provider

## Tool Choice

Uses **GCC gcov + lcov** for native GCC integration, zero dependencies, and mature tooling.

## Results

Initial coverage (unit tests):
- Line: 58.2% (7,114 of 12,225 lines)
- Function: 73.0% (621 of 851 functions)
- Branch: 37.1% (3,247 of 8,751 branches)
