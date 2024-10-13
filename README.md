# Symbolic Execution: Buffer Overflow Analysis with Z3 and Angr

This repository contains various demonstration programs for analyzing buffer overflow vulnerabilities using both Z3 theorem prover and Angr symbolic execution engine. The programs include vulnerable C++ code examples and symbolic execution files to help explore and mitigate buffer overflow attacks.

## File Descriptions

### `z3-bufferoverflow.cpp`
This file contains a vulnerable C++ code that can be exploited via a buffer overflow attack. It serves as the target for symbolic analysis to detect the vulnerability.

### `z3-symbolic-exec.py`
This Python script performs symbolic execution using the Z3 solver on the constraints found in the `z3-bufferoverflow.cpp` file, helping to analyze the conditions under which a buffer overflow might occur.

### `demo-bufferoverflow-gets.cpp`
This file contains another vulnerable C++ code similar to `z3-bufferoverflow.cpp` but uses the unsafe `gets()` function, which is notorious for being vulnerable to buffer overflow attacks.

### `angr-sse-bufferoverflow.py`
This script utilizes the Angr symbolic execution engine to analyze the compiled version of the vulnerable C++ file, detecting paths where buffer overflow vulnerabilities could be triggered.

### `angr-sse-bufferoverflow-directed.py`
This script uses Angr to perform directed symbolic execution on the compiled vulnerable C++ file, focusing on specific execution paths that lead to potential vulnerabilities like buffer overflows.

## Requirements

- **Z3 Solver**: Install the Z3 Python bindings with the following command:
  
  ```bash
  pip install z3-solver

- **Angr**: Install the Angr framework with the following command:
  
  ```bash
  pip install angr