# V8 Sandbox Escape Fix

This repository contains the patch for a V8 sandbox escape vulnerability
affecting V8 15.x (and earlier versions back to Chrome 103, ~June 2022).

## Vulnerability

Corrupting both a SandboxedPtr data pointer field and its associated
BoundedSize byte_length field in JSArrayBuffer, JSDataView, or
JSTypedArray allows reads and writes past the V8 sandbox boundary.
The root cause: the memory access pipeline checks `offset < byte_length`
but never checks `base_pointer + offset < sandbox_end`.

Two independent escape primitives are confirmed:
1. DataView escape via JSDataView.data_pointer_ (pure JavaScript)
2. Wasm escape via JSArrayBuffer.backing_store_ (~2GB OOB range)

## Patch

The patch adds SBXCHECK validation in the C++ accessor methods for the
three affected SandboxedPtr data pointer fields, plus a CSA_CHECK in
the Torque/CSA access path.

### Files Modified

- `src/sandbox/sandboxed-pointer-inl.h` - defense-in-depth SBXCHECK
- `src/objects/js-array-buffer-inl.h` - SBXCHECK in three accessors
- `src/codegen/code-stub-assembler.cc` - CSA_CHECK in CSA path

### Applying the Patch

```bash
# Clone V8
git clone https://chromium.googlesource.com/v8/v8.git
cd v8

# Apply patch (adjust commit hash as needed)
git apply patches/0001-validate-sandboxed-ptr-bounded-size-boundary.patch

# Build
tools/dev/gm.py x64.sandbox

# Test with PoC (should now trigger SBXCHECK instead of escape)
./out/x64.sandbox/d8 --sandbox-testing escape_dv.js
```

After the patch, the PoC will trigger a CHECK failure (process abort)
instead of allowing out-of-sandbox memory access.

## Repository Structure

```
patches/
  0001-validate-sandboxed-ptr-bounded-size-boundary.patch
PATCH.md          - Detailed patch rationale and analysis
PATCH_DIFF.md     - Annotated diff with inline comments
README.md         - This file
```
