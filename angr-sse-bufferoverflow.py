import angr
import sys

# angr.Project() Loads the binary into Angr for analysis.
proj = angr.Project(sys.argv[1], auto_load_libs=False)

# Define the entry point for analysis
# entry_state(): Creates an initial state at the binary's entry point, representing the start of execution.
state = proj.factory.entry_state()

# Create a simulation manager to handle symbolic execution paths
# simulation_manager(): Manages the symbolic execution paths. You can use this to explore different execution paths.
simgr = proj.factory.simulation_manager(state)

# Explore paths until reaching program termination
# simgr.explore(): Tells Angr to explore all possible execution paths in the binary.
simgr.explore()

# Check the results
# simgr.found: After exploration, this stores the paths where the program terminates (or meets specific conditions like hitting a vulnerability).
if simgr.found:
    found_state = simgr.found[0]
    print("Found a terminating state!")
    print(found_state.posix.dumps(0))  # Input that led to this state
else:
    print("No terminating state found.")