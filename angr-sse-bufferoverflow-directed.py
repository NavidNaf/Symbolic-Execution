import angr
import claripy
import sys

# Load the binary into angr
proj = angr.Project(sys.argv[1], auto_load_libs=False)

# Create a symbolic input (a buffer of symbolic bytes)
input_size = 20  # Trying input of size 20
input_str = claripy.BVS('input_str', input_size * 8)  # 8 bits per byte

# Create a state where the input is provided to the program
state = proj.factory.full_init_state(stdin=input_str)

# Define a simulation manager to explore the binary
simgr = proj.factory.simulation_manager(state)

# Explore paths and look for crashes (e.g., buffer overflow or segmentation fault)
simgr.explore(find=lambda s: b'You entered:' in s.posix.dumps(1),  # Normal output
              avoid=lambda s: s.addr == 0x400000)  # Example of avoiding address 0x400000 (crash)

# Check the result
if simgr.found:
    found_state = simgr.found[0]
    print("Found a path!")
    # This will show the symbolic input that triggered the path
    print(found_state.posix.dumps(0))  # This shows the input that led to the successful path
else:
    print("No valid paths found.")
