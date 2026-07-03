# dSBOM-engine

Non-invasive runtime Software Bill of Materials (SBOM) generation engine. The system derives component identity, linkage, and cryptographic integrity assertions natively from the Linux kernel virtual filesystem (VFS) and tracer subsystems, eliminating userspace injection, application instrumentation, or static manifest approximation.
## 1. Architectural Framework
### 1.1 Kernel Boundary Interception

The engine isolates and tracks target process hierarchies entirely from the host context using `ptrace(2)`. Address space transparency is maintained through an external, register-level observation loop driven by `PTRACE_SYSCALL` with `PTRACE_O_TRACESYSGOOD` enabled.

```bash

Host Context (dSBOM-engine)
  │
  ├──► PTRACE_SYSCALL ──► [Kernel VFS / Syscall Boundary]
  │                             │
  │     ┌───────────────────────┴───────────────────────┐
  │     ▼ (SIGTRAP | 0x80)                              ▼ (/proc/[pid]/root)
  └─── Decode Registers (orig_rax)               Secure Path Resolution
        ├── SYS_execve (Reset Ledger)                   └── Chunked mmap()
        └── SYS_mmap / SYS_mprotect                     └── OpenSSL EVP Stream
```

The tracing state machine decodes the x86-64 register file at every syscall entry-exit boundary to capture lifecycle-critical state changes:

    SYS_execve (59) / SYS_execveat (322): Resets the per-task dynamic mapping ledger and initiates a new component lifecycle evaluation.

    SYS_mmap (9): Extracts length, page protection flags (prot), and file descriptors to track valid file-backed virtual memory allocations.

    SYS_mprotect (10): Monitors memory region permission transitions, flag modifications, and write-or-execute (W^X) violations.

### 1.2 Isolated Namespace Translation

To inspect targets inside isolated runtimes (e.g., Docker, Podman, containerd) without cross-boundary data leakage, file I/O operations are routed through the target process's virtual path root:

```bash

/proc/[pid]/root/[canonical-internal-path]
```

The kernel translates this path by traversing the target's mount namespace dentry cache. This structural routing allows the host-resident engine to read targets and runtime shared libraries directly, executing static ELF analysis and verification signatures without performing `setns(2)` or `pivot_root`, keeping host filesystem isolation primitives intact.

### 1.3 Cryptographic Integrity Pipeline

The hashing subsystem implements an allocation-free pipeline centered around a pre-allocated, thread-local OpenSSL `EVP_MD_CTX` context configured for SHA-256.

    Zero Heap Allocation: The execution context is stack-allocated once per worker thread. Intermediate digests are collected directly into a fixed-size buffer and hex-encoded using a constexpr lookup table.

    Page-Aligned Streaming: Files are read sequentially in 64 KiB page-aligned chunks using mmap(2) with MAP_PRIVATE and MADV_SEQUENTIAL hints, minimizing TLB pressure and eliminating runtime userspace buffer allocations.

## 2. Repository Architecture

```bash

./
├── CMakeLists.txt              # Unified build configuration
├── include/                    # Architectural header declarations
│   ├── artifact_generator.hpp
│   ├── memory_sniffer.hpp
│   └── process_spawner.hpp
├── src/                        # Implementation units
│   ├── artifact_generator.cpp  # Hashing pipeline & CycloneDX serialization
│   ├── main.cpp                # ptrace lifecycle engine loop
│   ├── memory_sniffer.cpp      # /proc/[pid]/maps VMA parsing engine
│   └── process_spawner.cpp     # Target context & fork synchronization
├── tests/                      # Validation suites
│   ├── basic_link.c
│   ├── dynamic_load.c
│   ├── fork_tree.c
│   ├── memory_injections.c
│   └── stress_syscall.c
└── run_tests.sh                # Automated orchestration harness
```

## 3. Prerequisites & System Dependencies

    OS: Linux Kernel 5.4+ (Enforcing proper ptrace and user_namespaces interaction semantics).

    Toolchain: GCC 11+ / Clang 13+ fully compliant with the ISO C++20 specification.

    Build Tool: CMake 3.22+.

    Libraries: OpenSSL 1.1.1 or 3.x development headers (libssl-dev).

    Privileges: CAP_SYS_PTRACE is mandatory for tracking target threads. CAP_SYS_ADMIN is required if target workloads inhabit non-descendant user namespaces.

## 4. Compilation Pipeline

Out-of-source compilation is required to protect workspace state.
Bash

```bash
# Production Release Build
cmake -B build \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_CXX_FLAGS="-O3 -fno-rtti -fno-exceptions"
cmake --build build --parallel $(nproc)

# Debug Build with Tooling Sanitizers
cmake -B build_debug \
      -DCMAKE_BUILD_TYPE=Debug \
      -DENABLE_ASAN=ON \
      -DENABLE_UBSAN=ON
cmake --build build_debug
```

## 5. Deployment Model
### 5.1 Execution

The engine must run with `CAP_SYS_PTRACE` configured in the ambient set or within an administrative root context:

```bash
sudo setcap cap_sys_ptrace=ep build/dSBOM-engine
./build/dSBOM-engine --target /usr/bin/app --output runtime-sbom.json
```

### 5.2 Command Line Interface

```bash

dSBOM-engine --target <binary_path_or_pid>
             [--output <file>]          # Default: stdout
             [--timeout <seconds>]      # Hard execution bounds
             [--include-kernel]         # Force vDSO / vvar tracking
             [--verbose]                # Syscall telemetry log
```

### 5.3 Automated Validation Suite

The test harness compiles runtime simulations inside `tests/` to validate edge conditions (aggressive fork storms, runtime library evaluations via `dlopen`, anonymous memory permissions, and high-frequency syscall streams):

```bash
chmod +x run_tests.sh
sudo ./run_tests.sh --engine ./build/dSBOM-engine --output-dir ./test_results
```

## 6. Output Specifications

The system emits fully schema-validated CycloneDX 1.5 JSON records. Component types are verified dynamically based on binary structure (`ET_EXEC` vs `ET_DYN`).

```JSON

{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:70b16d4f-bb5d-4a3d-bc41-7c1778d6129f",
  "version": 1,
  "metadata": {
    "timestamp": "2026-07-03T14:22:01Z",
    "tools": [
      {
        "vendor": "dSBOM",
        "name": "dSBOM-engine",
        "version": "0.2.0"
      }
    ]
  },
  "components": [
    {
      "type": "library",
      "name": "libc.so.6",
      "version": "dynamic-runtime",
      "scope": "required",
      "hashes": [
        { "alg": "SHA-256", "content": "9bf40a540836d90c7d46c95eeb222a217597834eea29ab9e537428317c021c3a" }
      ],
      "evidence": {
        "identity": [
          {
            "field": "path",
            "concludedValue": "/usr/lib/libc.so.6",
            "methods": [
              {
                "technique": "ptrace",
                "confidence": 1.0,
                "value": "/usr/lib/libc.so.6"
              }
            ]
          }
        ]
      }
    }
  ]
}
```

## 7. Governance & Licensing

This project is open-source software licensed strictly under the terms of the **MIT License**. Contributions require adherence to the Developer Certificate of Origin (DCO) via signed commits. Cryptographic verification functions depend on the OpenSSL project under the Apache License 2.0.
