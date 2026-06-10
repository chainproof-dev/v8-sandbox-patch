# Patch: Validate SandboxedPtr + BoundedSize Combination Against Sandbox Boundary

## Summary

This patch fixes a V8 sandbox escape vulnerability where corrupting both a
SandboxedPtr data pointer field and its associated BoundedSize byte_length
field allows reads and writes past the sandbox boundary.

The root cause is that the memory access pipeline checks `offset < byte_length`
but never checks `base_pointer + offset < sandbox_end`.  The SandboxedPtr
encoding guarantees the decoded base is within the sandbox, and BoundedSize
limits the maximum decoded value to ~32GB.  When both fields are corrupted,
the base can be near sandbox_end and the byte_length can be large enough that
base + byte_length exceeds the sandbox boundary, and the software bounds check
(offset < byte_length) does not catch this.

## Files Modified

1. `src/sandbox/sandboxed-pointer-inl.h`
   - Added `SBXCHECK(Sandbox::current()->Contains(pointer))` in
     `ReadSandboxedPointerField` to validate the decoded pointer is within the
     sandbox.  This is defense in depth: the encoding guarantees this by
     construction, but the explicit check catches any corruption of the stored
     encoded value that might produce an unexpected decode result.

2. `src/objects/js-array-buffer-inl.h`
   - `JSArrayBuffer::backing_store(PtrComprCageBase)`: Added SBXCHECK that
     `backing_store + byte_length <= sandbox_end`.  This is the primary fix
     for the Wasm escape vector.
   - `JSDataViewOrRabGsabDataView::data_pointer(PtrComprCageBase)`: Added
     SBXCHECK that `data_pointer + byte_length <= sandbox_end`.  This is the
     primary fix for the DataView escape vector (pure JavaScript, no Wasm).
   - `JSTypedArray::external_pointer(PtrComprCageBase)`: Added SBXCHECK that
     `external_pointer + byte_length <= sandbox_end` for off-heap typed
     arrays.  On-heap typed arrays store data in the V8 heap which is
     sandbox-contained, so the check is only applied to the off-heap case.

3. `src/codegen/code-stub-assembler.cc`
   - `LoadJSArrayBufferBackingStorePtr`: Added CSA_CHECK that the decoded
     backing_store pointer plus the decoded byte_length does not exceed
     sandbox_end.  This covers the Torque/CSA DataView access path, which
     loads the backing store pointer through this function and then uses it
     with an offset for memory access without further sandbox boundary checks.

## Rationale

The V8 sandbox design uses three mechanisms to prevent memory corruption from
escaping the sandbox:

1. SandboxedPtr encoding ensures the base pointer decodes within the sandbox
2. BoundedSize encoding limits size values to a maximum of ~32GB
3. Guard regions (32GB+ of virtual address reservation) catch accidental OOB

The design assumes these three together prevent escape.  This assumption fails
when both the SandboxedPtr and BoundedSize fields of the same object are
corrupted, because:

- SandboxedPtr guarantees base in sandbox, but NOT base + offset in sandbox
- BoundedSize limits max value to 32GB, but 32GB far exceeds the remaining
  space between a near-boundary base pointer and sandbox_end
- Guard regions are virtual address reservations, not hardware-enforced
  memory protection.  Mapped pages in the guard region are accessible.

The fix adds the missing check: `base + byte_length <= sandbox_end`.  This
invariant should always hold for legitimately allocated objects (backing stores
are allocated inside the sandbox, and byte_length matches the allocation size).
If either field is corrupted, the SBXCHECK fires before any out-of-sandbox
memory access can occur.

## Why SBXCHECK

The SBXCHECK macro is specifically designed for this scenario.  From check.h:

  "An SBXCHECK behaves like a CHECK, but indicates that the check is required
   for the sandbox, i.e. prevents a sandbox bypass."

  "With the sandbox attacker model, we have to assume that the in-sandbox
   object can be corrupted by an attacker and so the access can go
   out-of-bounds.  In that case, a SBXCHECK can be used to both prevent
   memory corruption outside of the sandbox and document that there is a
   security-critical invariant that may be violated when an attacker can
   corrupt memory inside the sandbox, but otherwise holds true."

This is exactly our situation: the invariant `base + byte_length <= sandbox_end`
holds for legitimate objects but can be violated by in-sandbox corruption.

## Performance Impact

The SBXCHECK adds one comparison per call to the affected accessor methods.
These accessors are called at the following frequencies:

- `backing_store()`: Called during ArrayBuffer operations, GC, serialization.
  The check adds one addition and one comparison.  Negligible overhead.

- `data_pointer()`: Called when accessing DataView fields from C++ runtime.
  The Torque/CSA path is covered by the CSA_CHECK in
  LoadJSArrayBufferBackingStorePtr.  Negligible overhead.

- `external_pointer()`: Called during TypedArray setup and access from C++.
  The is_on_heap() check adds one comparison, and the SBXCHECK adds one
  addition and one comparison for off-heap arrays.  Negligible overhead.

The CSA_CHECK in LoadJSArrayBufferBackingStorePtr adds one load (sandbox_end
from external constant), one addition, and one comparison to the Torque/CSA
DataView access path.  This is minimal overhead for a security-critical check.

## What This Patch Does NOT Cover

This patch covers the three confirmed SandboxedPtr data pointer fields in the
ArrayBuffer/DataView/TypedArray family and the primary Torque/CSA access path
for DataView operations.  The following code paths are not modified but should
be considered for follow-up patches:

1. Maglev DataView/TypedArray access: The Maglev JIT compiler generates
   direct memory access code for DataView and TypedArray operations.  These
   paths load the data pointer and compute base + offset without a sandbox
   boundary check.  A separate patch is needed for Maglev.

2. Turboshaft DataView/TypedArray access: Similar to Maglev, the Turboshaft
   JIT compiler generates direct memory access code.  A separate patch is
   needed.

3. Wasm memory access: The Wasm memory access path loads memory0_start from
   WasmTrustedInstanceData (a raw pointer in trusted space).  When the
   underlying ArrayBuffer's backing_store is corrupted, the C++ runtime
   propagates the new value into memory0_start via SetRawMemory.  The
   SBXCHECK in backing_store() catches this at propagation time, but a
   direct check in the Wasm memory access path would be more comprehensive.

These paths are lower priority because they require modifying JIT code
generators, which is more complex and has higher risk of performance
regression.  The C++ and CSA level checks in this patch are sufficient to
prevent the confirmed exploit paths from escaping the sandbox.
