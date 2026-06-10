# Applying the Patch

## Quick Start

```bash
# Clone V8 source
git clone https://chromium.googlesource.com/v8/v8
cd v8

# Apply the patch
git apply patches/v2-full-patch.patch

# Build with sandbox enabled
tools/dev/gm.py x64.release d8

# Test with --sandbox-testing
./out/x64.release/d8 --sandbox-testing escape_dv.js
./out/x64.release/d8 --sandbox-testing escape_wasm.js
```

## Patch Files

- `v2-full-patch.patch` — Complete patch including v1 defense-in-depth and v2
  primary fix.  Apply to a clean V8 checkout.
- `v2-sandbox-pointer-bounds-check.patch` — v2 changes only (on top of v1).

## Expected Behavior

On the **unpatched** build, both PoCs demonstrate sandbox escape:
- `escape_dv.js`: DataView data_pointer_ + raw_byte_length_ corruption → ~2GB OOB
- `escape_wasm.js`: ArrayBuffer backing_store_ + raw_byte_length_ corruption → ~2GB OOB

On the **patched** build (v2):
- Both PoCs should trigger a sandbox violation check and crash (ud2/SIGILL)
  instead of completing the escape.
- The crash occurs at the first data pointer access that violates the
  `data_pointer + byte_length <= sandbox_end` invariant.

## Build Configuration

The patch requires:
- `v8_enable_sandbox = true` (default in recent V8)
- `v8_enable_memory_corruption_api = true` (for --sandbox-testing)
