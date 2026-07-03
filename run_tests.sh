#!/bin/bash
set -euo pipefail

ENGINE="./build/dSBOM"
TEST_DIR="./build"


if [[ ! -x "$ENGINE" ]]; then
    echo -e "[!] Error: dSBOM engine not found or not executable  $ENGINE"
    exit 1
fi

run_target_test() {
    local target_name=$1
    local target_path="${TEST_DIR}/${target_name}"

    if [[ ! -x "$target_path" ]]; then
        echo -e "[!] Skipping ${target_name} - Binary not found."
        return 0
    fi

    echo -e "[*] Initiating: ${target_name}"

    "$ENGINE" "$target_path"

    echo -e "[+] Complete: ${target_name}\n\n"
}

run_target_test "basic_link"
run_target_test "dynamic_load"
run_target_test "memory_injections"
run_target_test "stress_syscall"
run_target_test "fork_tree"