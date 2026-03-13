#!/bin/bash
# Count memory allocation patterns across libfabric directories

DIRS="prov/efa/src prov/shm/src prov/util/src src include"

PATTERNS=(
  "malloc|calloc"
  "realloc"
  "strdup|strndup"
  "mmap|munmap"
  "aligned_alloc|posix_memalign"
  "ofi_bufpool|ofi_buf_alloc|ofi_buf_free"
  "smr_freestack|freestack_size|freestack_init"
)

LABELS=(
  "malloc/calloc"
  "realloc"
  "strdup/strndup"
  "mmap/munmap"
  "aligned/memalign"
  "ofi_bufpool"
  "smr_freestack"
)

# Compute max label width
max_lw=0
for label in "${LABELS[@]}"; do
  (( ${#label} > max_lw )) && max_lw=${#label}
done
W=$(( max_lw + 2 ))

# Compute max dir width
max_dw=9 # "Directory"
for dir in $DIRS; do
  (( ${#dir} > max_dw )) && max_dw=${#dir}
done
DW=$(( max_dw + 2 ))

# Print header
printf "%-${DW}s" "Directory"
for label in "${LABELS[@]}"; do
  printf "%${W}s" "$label"
done
echo

# Print separator
printf "%-${DW}s" ""
for label in "${LABELS[@]}"; do
  printf "%${W}s" "$(printf '%0.s-' $(seq 1 ${#label}))"
done
echo

# Print counts per directory
for dir in $DIRS; do
  printf "%-${DW}s" "$dir"
  for pat in "${PATTERNS[@]}"; do
    count=$(grep -rnE "\b($pat)\b" "$dir" 2>/dev/null | wc -l | tr -d ' ')
    printf "%${W}s" "$count"
  done
  echo
done
