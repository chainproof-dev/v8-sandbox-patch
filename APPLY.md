# Applying the Patch

## Prerequisites

- Linux x64 system
- Depot tools installed (`fetch v8` workflow)
- Build dependencies met

## Step-by-Step

### 1. Get V8 Source

```bash
mkdir v8-work && cd v8-work
fetch v8
cd v8
gclient sync
```

### 2. Apply the Patch

```bash
git apply patches/0001-validate-sandboxed-ptr-bounded-size-boundary.patch
```

If the patch does not apply cleanly (due to upstream changes), you can
apply the changes manually using the annotated diff in PATCH_DIFF.md.

### 3. Build V8 with Sandbox Enabled

```bash
tools/dev/gm.py x64.sandbox
```

Or manually:

```bash
gn gen out/x64.sandbox --args='
  is_debug = false
  v8_enable_sandbox = true
  v8_enable_memory_corruption_api = true
'
ninja -C out/x64.sandbox d8
```

### 4. Verify the Fix

Run the DataView PoC against the patched build:

```bash
./out/x64.sandbox/d8 --sandbox-testing escape_dv.js
```

Expected behavior on patched build: the process aborts with a CHECK
failure (SBXCHECK fires when base + byte_length exceeds sandbox_end),
instead of printing the escape confirmation.

Run the Wasm PoC:

```bash
./out/x64.sandbox/d8 --sandbox-testing escape_wasm.js
```

Same expectation: SBXCHECK fires, process aborts, no escape.

### 5. Verify No Regression

Run V8's existing test suite to confirm the patch does not break
legitimate functionality:

```bash
tools/run-tests.py --outdir=out/x64.sandbox
```
