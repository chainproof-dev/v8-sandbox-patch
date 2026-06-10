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

## Revision History

### v2 — JIT-level and Torque-level validation

The initial patch (v1) added SBXCHECK to C++ accessors and a CSA_CHECK to
`LoadJSArrayBufferBackingStorePtr`.  This was insufficient because:

- **C++ accessors are not on the hot path**: JIT-compiled code (Maglev,
  TurboFan) bypasses C++ accessors entirely, loading data pointers via
  `LoadSandboxedPointerField` (which only decodes, no bounds check) and
  computing `base + offset` without validating against sandbox_end.
- **The Torque DataView builtin uses `buffer.backing_store_ptr`**, not
  `dataView.data_pointer_`.  The existing CSA_CHECK validates the ArrayBuffer's
  backing_store (which is not corrupted in the DataView attack), but does not
  detect corruption of the DataView's own `data_pointer_` field.

v2 adds the missing validation at the actual data pointer access points in the
JIT compilers and the Torque builtins.

### v1 — C++ accessor and CSA-level validation (superseded)

Added SBXCHECK to C++ accessors (`backing_store()`, `data_pointer()`,
`external_pointer()`) and a CSA_CHECK to `LoadJSArrayBufferBackingStorePtr`.
These remain as defense-in-depth layers but do not prevent escape through JIT
code paths.

## Files Modified

### Defense in Depth (v1, still present)

1. `src/sandbox/sandboxed-pointer-inl.h`
   - Added `SBXCHECK(Sandbox::current()->Contains(pointer))` in
     `ReadSandboxedPointerField` to validate the decoded pointer is within
     the sandbox.  Defense in depth: the encoding guarantees this by
     construction.

2. `src/objects/js-array-buffer-inl.h`
   - `JSArrayBuffer::backing_store(PtrComprCageBase)`: SBXCHECK that
     `backing_store + byte_length <= sandbox_end`.
   - `JSDataViewOrRabGsabDataView::data_pointer(PtrComprCageBase)`: SBXCHECK
     that `data_pointer + byte_length <= sandbox_end`.
   - `JSTypedArray::external_pointer(PtrComprCageBase)`: SBXCHECK that
     `external_pointer + byte_length <= sandbox_end` for off-heap arrays.

3. `src/codegen/code-stub-assembler.cc`
   - `LoadJSArrayBufferBackingStorePtr`: CSA_CHECK that decoded
     backing_store + byte_length <= sandbox_end.  Covers the Torque/CSA
     DataView access path (which uses `buffer.backing_store_ptr`).

### Primary Fix (v2, new)

4. `src/codegen/x64/macro-assembler-x64.h` / `.cc`
   - New `SandboxedPointerBoundsCheck(Register, Register)` helper in the x64
     MacroAssembler.  Checks `byte_length <= sandbox_end - decoded_pointer`
     using only `kScratchRegister`.  Traps with `ud2()` on violation.
     Guarded by `#ifdef V8_ENABLE_SANDBOX`.

5. `src/maglev/maglev-ir.cc` — `LoadDataViewDataPointer::GenerateCode`
   - After loading `data_pointer_` via `LoadExternalPointerField`, loads
     `raw_byte_length_` and calls `SandboxedPointerBoundsCheck`.  This
     covers the Maglev JIT path for DataView operations, which uses
     `data_pointer_` directly (unlike the Torque builtin that uses
     `buffer.backing_store_ptr`).

6. `src/maglev/x64/maglev-assembler-x64-inl.h` — `BuildTypedArrayDataPointer`
   - After loading `external_pointer_` via `LoadExternalPointerField` (and
     before adding `base_pointer_`), loads `raw_byte_length_` and calls
     `SandboxedPointerBoundsCheck`.  This covers the Maglev JIT path for
     TypedArray element access.

7. `src/codegen/code-stub-assembler.h` / `.cc` — `LoadJSTypedArrayExternalPointerPtr`
   - Moved from inline definition in the header to out-of-line definition in
     the .cc file.  Added CSA_CHECK that `external_pointer + byte_length <=
     sandbox_end`, matching the pattern in `LoadJSArrayBufferBackingStorePtr`.
     Covers the Torque/CSA TypedArray access path.

8. `src/codegen/code-stub-assembler.h` / `.cc` — `ValidateJSDataViewDataPointerBounds`
   - New CSA function that loads the DataView's `data_pointer_` and
     `raw_byte_length_` and validates `data_pointer + byte_length <=
     sandbox_end`.  Called from the Torque DataView builtins as defense in
     depth, even though those builtins access data through
     `buffer.backing_store_ptr`.

9. `src/builtins/data-view.tq` — `DataViewGet` and `DataViewSet`
   - Added `extern macro ValidateJSDataViewDataPointerBounds(...)` declaration.
   - Added `ValidateJSDataViewDataPointerBounds(dataView)` call in both
     `DataViewGet` and `DataViewSet`, after the detached/out-of-bounds check
     but before the actual data access.  Detects corruption of `data_pointer_`
     or `raw_byte_length_` even when the access goes through
     `buffer.backing_store_ptr`.

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
If either field is corrupted, the check fires before any out-of-sandbox memory
access can occur.

## Why SBXCHECK and CSA_CHECK

The SBXCHECK macro is specifically designed for this scenario.  From check.h:

  "An SBXCHECK behaves like a CHECK, but indicates that the check is required
   for the sandbox, i.e. prevents a sandbox bypass."

  "With the sandbox attacker model, we have to assume that the in-sandbox
   object can be corrupted by an attacker and so the access can go
   out-of-bounds.  In that case, a SBXCHECK can be used to both prevent
   memory corruption outside of the sandbox and document that there is a
   security-critical invariant that may be violated when an attacker can
   corrupt memory inside the sandbox, but otherwise holds true."

CSA_CHECK is the CodeStubAssembler equivalent, generating machine code that
performs the same validation at runtime in Torque/CSA builtins.

In Maglev, the `SandboxedPointerBoundsCheck` MacroAssembler helper emits
equivalent machine code: load sandbox_end, compute sandbox_end - base, compare
with byte_length, and trap (ud2) on violation.

## Performance Impact

The checks add one sandbox_end load, one subtraction, one BoundedSize load
(with shift), and one comparison per data pointer access.  This is ~8
additional instructions per DataView/TypedArray operation in the affected code
paths.  For security-critical sandbox boundary validation, this overhead is
acceptable and consistent with V8's existing SBXCHECK usage patterns.

## What This Patch Does NOT Cover

1. TurboFan/Turboshaft TypedArray and DataView access: The optimizing
   compiler generates direct memory access code for hot operations.  These
   paths load data pointers via `MachineType::SandboxedPointer()` without
   sandbox boundary validation.  A separate patch is needed for TurboFan.

2. Architecture-specific Maglev implementations other than x64: The
   `SandboxedPointerBoundsCheck` helper is only implemented for x64.  Arm64,
   RISC-V, Loong64, and other architectures need equivalent implementations.

3. Wasm memory access: The Wasm compiled code uses `memory0_start` (a raw
   pointer in trusted space) with bounds checks against `memory0_size`.
   Corrupting the JSArrayBuffer's `backing_store_` after Wasm memory setup
   does NOT affect the Wasm access path (it uses cached trusted values).
   The C++ accessor SBXCHECK catches corruption at propagation time if the
   memory is re-configured.
