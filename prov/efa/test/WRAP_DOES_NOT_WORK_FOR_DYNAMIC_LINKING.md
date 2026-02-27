# CRITICAL DISCOVERY: --wrap Does Not Work for Dynamic Linking

## The Problem

The `--wrap` linker flag creates `__wrap_symbol` and `__real_symbol` for static linking, but it does NOT work for dynamic symbol resolution!

When code inside `libfabric.so` calls `ibv_get_device_list()`, the dynamic linker resolves it to the symbol in `libibverbs.so`, NOT to `__wrap_ibv_get_device_list` in the test binary.

## Why This Matters

All our rdma-core function wrappers (`ibv_get_device_list`, `ibv_open_device`, `ibv_query_device`, etc.) were NOT being called during provider initialization, even though:
- The `--wrap` flags were in the Makefile
- The `__wrap_` symbols existed in the test binary (verified with `nm`)
- The test binary was linked with `-rdynamic` and `--export-dynamic`

## The Solution

Create symbol aliases using `__attribute__((alias(...)))` to make the unwrapped symbol name point to the wrapped version:

```c
// In the same translation unit as __wrap_ibv_get_device_list
struct ibv_device** ibv_get_device_list(int *num) 
    __attribute__((alias("__wrap_ibv_get_device_list"), visibility("default")));
```

This creates an exported symbol `ibv_get_device_list` that points to `__wrap_ibv_get_device_list`. With `-rdynamic` and `--export-dynamic`, the dynamic linker will now resolve calls from `libfabric.so` to our test binary's symbol instead of `libibverbs.so`.

## Verification

Before adding alias:
```bash
$ LD_DEBUG=symbols,bindings ./test 2>&1 | grep "ibv_get_device_list"
symbol=ibv_get_device_list;  lookup in file=./test [0]
symbol=ibv_get_device_list;  lookup in file=./libfabric.so.1 [0]
...
symbol=ibv_get_device_list;  lookup in file=/lib/libibverbs.so.1 [0]
# Found in libibverbs.so.1 - our wrapper NOT called!
```

After adding alias:
```bash
$ ./test 2>&1 | grep "DEBUG"
DEBUG: __wrap_ibv_get_device_list called (call #1)
# Our wrapper IS called!
```

## The Challenge

We need to create aliases for ALL wrapped functions:
- `ibv_get_device_list`
- `ibv_free_device_list`
- `ibv_get_device_name`
- `ibv_open_device`
- `ibv_close_device`
- `ibv_query_device`
- `ibv_query_port`
- `ibv_query_gid`
- ... and many more

But we can't declare these in a file that includes `verbs.h` because of symbol conflicts.

## Possible Solutions

1. **Linker version script**: Use a version script to create the aliases at link time
2. **Separate compilation unit**: Create aliases in a .c file without including verbs.h (requires extern declarations)
3. **Preprocessor tricks**: Use `#define` to rename symbols before including verbs.h
4. **Pragma workarounds**: Use compiler pragmas to suppress redeclaration warnings
5. **Accept limitation**: Document that only some wrappers work and tests must be designed accordingly

## Impact

This discovery explains why:
- The lazy initialization approach wasn't working
- The lock was never initialized (provider never ran with our mocks)
- Tests were crashing (provider was calling real rdma-core functions on our mock devices)

## Next Steps

Need to implement one of the solutions above to create aliases for all wrapped functions, enabling full mock functionality for unit tests.
