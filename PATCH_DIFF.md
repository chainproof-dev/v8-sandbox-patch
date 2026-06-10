# Patch Diff

Generated against V8 commit: c73144da (V8 15.1.0 candidate)

## File: src/sandbox/sandboxed-pointer-inl.h

```diff
@@ -10,6 +10,7 @@
 #include "include/v8-internal.h"
 #include "src/common/ptr-compr-inl.h"
+#include "src/sandbox/check.h"
 #include "src/sandbox/sandbox.h"

 namespace v8 {
@@ -21,6 +22,13 @@
   SandboxedPointer_t sandboxed_pointer =
       base::ReadUnalignedValue<SandboxedPointer_t>(field_address);

   Address offset = sandboxed_pointer >> kSandboxedPointerShift;
   Address pointer = cage_base.address() + offset;
+  // The SandboxedPtr encoding guarantees the decoded pointer falls within
+  // the sandbox by construction.  Verify this invariant as defense in depth:
+  // if in-sandbox data has been corrupted, the decoded base could still lie
+  // inside the sandbox, but subsequent pointer arithmetic (base + offset)
+  // might escape it.  The per-field SBXCHECK in the data-pointer accessors
+  // (backing_store, data_pointer, external_pointer) catches that case.
+  SBXCHECK(Sandbox::current()->Contains(pointer));
   return pointer;
 #else
```

## File: src/objects/js-array-buffer-inl.h

### JSArrayBuffer::backing_store

```diff
@@ -63,6 +63,15 @@
 void* JSArrayBuffer::backing_store(PtrComprCageBase cage_base) const {
   Address value = ReadSandboxedPointerField(
       offsetof(JSArrayBuffer, backing_store_), cage_base);
+#ifdef V8_ENABLE_SANDBOX
+  // The sandbox threat model assumes an attacker can corrupt in-sandbox data
+  // arbitrarily.  If both backing_store_ (SandboxedPtr) and raw_byte_length_
+  // (BoundedSize) are corrupted, the decoded base pointer is still inside the
+  // sandbox, but base + byte_length can exceed sandbox_end.  Subsequent
+  // memory accesses that only check offset < byte_length will then read or
+  // write past the sandbox boundary.  Validate the combined invariant here.
+  size_t length = byte_length_unchecked();
+  SBXCHECK(value + length <= Sandbox::current()->end());
+#endif  // V8_ENABLE_SANDBOX
   return reinterpret_cast<void*>(value);
 }
```

### JSTypedArray::external_pointer

```diff
@@ -414,6 +414,16 @@
 Address JSTypedArray::external_pointer(PtrComprCageBase cage_base) const {
-  return ReadSandboxedPointerField(offsetof(JSTypedArray, external_pointer_),
-                                   cage_base);
+  Address value = ReadSandboxedPointerField(offsetof(JSTypedArray, external_pointer_),
+                                   cage_base);
+#ifdef V8_ENABLE_SANDBOX
+  // For off-heap typed arrays (base_pointer == Smi::zero), external_pointer_
+  // is the sole data pointer.  Validate that it plus the byte length does not
+  // escape the sandbox, consistent with the checks on backing_store and
+  // data_pointer.  On-heap typed arrays store data inside the V8 heap, which
+  // is sandbox-contained, so the check is only relevant for the off-heap case.
+  if (!is_on_heap()) {
+    size_t length = byte_length();
+    SBXCHECK(value + length <= Sandbox::current()->end());
+  }
+#endif  // V8_ENABLE_SANDBOX
+  return value;
 }
```

### JSDataViewOrRabGsabDataView::data_pointer

```diff
@@ -597,6 +597,14 @@
 void* JSDataViewOrRabGsabDataView::data_pointer(
     PtrComprCageBase cage_base) const {
   Address value = ReadSandboxedPointerField(
       offsetof(JSDataViewOrRabGsabDataView, data_pointer_), cage_base);
+#ifdef V8_ENABLE_SANDBOX
+  // Same invariant as JSArrayBuffer::backing_store: data_pointer +
+  // byte_length must not exceed the sandbox boundary.  Without this check,
+  // corrupting both data_pointer_ (SandboxedPtr) and raw_byte_length_
+  // (BoundedSize) allows base + offset to escape the sandbox even though
+  // each field individually appears valid.
+  size_t length = byte_length();
+  SBXCHECK(value + length <= Sandbox::current()->end());
+#endif  // V8_ENABLE_SANDBOX
   return reinterpret_cast<void*>(value);
 }
```

## File: src/codegen/code-stub-assembler.cc

### LoadJSArrayBufferBackingStorePtr

```diff
@@ -18651,8 +18651,23 @@
 TNode<RawPtrT> CodeStubAssembler::LoadJSArrayBufferBackingStorePtr(
     TNode<JSArrayBuffer> array_buffer) {
-  return LoadSandboxedPointerFromObject(
+  TNode<RawPtrT> backing_store = LoadSandboxedPointerFromObject(
       array_buffer, offsetof(JSArrayBuffer, backing_store_));
+#ifdef V8_ENABLE_SANDBOX
+  // The SandboxedPtr encoding guarantees the decoded base is inside the
+  // sandbox.  However, the Torque/CSA DataView and TypedArray access paths
+  // compute base + offset and check only offset < byte_length, without
+  // verifying that base + offset stays within the sandbox.  If both
+  // backing_store_ and raw_byte_length_ are corrupted (the sandbox threat
+  // model assumes arbitrary in-sandbox writes), base + offset can escape.
+  // Validate the invariant here so that any subsequent base + offset access
+  // that passed the byte_length check is guaranteed to stay in bounds.
+  TNode<UintPtrT> byte_length = LoadJSArrayBufferByteLength(array_buffer);
+  TNode<ExternalReference> sandbox_end_address =
+      ExternalConstant(ExternalReference::sandbox_end_address());
+  TNode<UintPtrT> sandbox_end = Load<UintPtrT>(sandbox_end_address);
+  TNode<UintPtrT> effective_end = UintPtrAdd(
+      ReinterpretCast<UintPtrT>(backing_store), byte_length);
+  CSA_CHECK(this, UintPtrLessThanOrEqual(effective_end, sandbox_end));
+#endif  // V8_ENABLE_SANDBOX
+  return backing_store;
 }
```
