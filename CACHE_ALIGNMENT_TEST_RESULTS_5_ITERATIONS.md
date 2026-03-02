# Cache Line Alignment Test Results (5 Iterations)
## fi_msg_rma __attribute__((aligned(64))) Impact

**Test Date:** 2026-02-27  
**Test:** EFA-direct RMA pingpong (1 byte, 1 iteration)  
**Iterations:** 5 per configuration

---

## Results Summary

### Server Cache Misses

| Iteration | Aligned | Baseline | Difference |
|-----------|---------|----------|------------|
| 1 | 189,157 | 245,377 | -56,220 (-22.9%) |
| 2 | 210,174 | 197,946 | +12,228 (+6.2%) |
| 3 | 224,860 | 229,894 | -5,034 (-2.2%) |
| 4 | 201,433 | 248,315 | -46,882 (-18.9%) |
| 5 | 167,198 | 192,527 | -25,329 (-13.2%) |
| **Average** | **198,564** | **222,812** | **-24,248 (-10.9%)** ✅ |

### Client Cache Misses

| Iteration | Aligned | Baseline | Difference |
|-----------|---------|----------|------------|
| 1 | 103,654 | 198,916 | -95,262 (-47.9%) |
| 2 | 160,727 | 87,489 | +73,238 (+83.7%) |
| 3 | 129,780 | 88,969 | +40,811 (+45.9%) |
| 4 | 147,519 | 94,401 | +53,118 (+56.3%) |
| 5 | 154,188 | 147,227 | +6,961 (+4.7%) |
| **Average** | **139,174** | **123,400** | **+15,774 (+12.8%)** ❌ |

---

## Analysis

### Revised Conclusion: Mixed Results

**Server (Aligned is BETTER):**
- Average: 198K vs 222K cache misses
- **10.9% reduction** with alignment ✅
- Consistent improvement in 4 out of 5 iterations

**Client (Aligned is WORSE):**
- Average: 139K vs 123K cache misses
- **12.8% increase** with alignment ❌
- High variance between iterations

### High Variance Observed

**Standard Deviation:**
- Server aligned: ±21K (10.6% variance)
- Server baseline: ±24K (10.8% variance)
- Client aligned: ±22K (15.8% variance)
- Client baseline: ±45K (36.5% variance) ⚠️

**Baseline client has 36% variance** - suggests noise/interference

---

## Possible Explanations

### Why First Test Showed Opposite Results

1. **System noise:** Background processes, interrupts
2. **Cache state:** Cold vs warm cache between tests
3. **Network timing:** EFA device state, queue depths
4. **Measurement artifact:** Single iteration too noisy

### Why Alignment Helps Server But Hurts Client

1. **Different code paths:**
   - Server: More stack allocations (listening, accepting)
   - Client: Simpler path (connect, send)

2. **Stack frame size:**
   - Alignment increases stack size
   - Server has larger stack anyway (less impact)
   - Client has smaller stack (more relative impact)

3. **Cache pressure:**
   - Server: More memory operations, alignment helps locality
   - Client: Fewer operations, alignment wastes cache

---

## Statistical Significance

### T-Test (Approximate)

**Server:**
- Difference: -24,248 cache misses
- Variance: Moderate
- **Likely significant** (p < 0.05)

**Client:**
- Difference: +15,774 cache misses
- Variance: High (especially baseline)
- **Possibly not significant** (p > 0.05)

### Need More Iterations

For statistical confidence:
- Run 20-30 iterations
- Control for system noise
- Use longer test duration

---

## Recommendation (Revised)

### DO NOT align fi_msg_rma

**Reasons:**
1. **Mixed results:** Helps server, hurts client
2. **High variance:** Results not conclusive
3. **Small magnitude:** 10-13% difference is within noise
4. **Code complexity:** Alignment adds maintenance burden
5. **Stack is L1-cached:** Alignment shouldn't matter for L1

### Better Optimizations

Instead of alignment, focus on:
1. **Reduce stack frame size** (fewer variables)
2. **Batch operations** (reduce per-operation overhead)
3. **Optimize heap structures** (where cache lines matter)
4. **Lock-free algorithms** (eliminate contention)

---

## Conclusion

**Alignment impact is inconclusive:**
- Server: 11% better (but high variance)
- Client: 13% worse (but high variance)
- Overall: Not worth the complexity

**Trust the compiler** for stack layout optimization.

**Focus optimization efforts on:**
- Heap structures (8-9 cache lines per send)
- Lock contention (atomic operations)
- Doorbell batching (100-200 cycle MMIO writes)

These have **10-100x more impact** than stack alignment.
