from z3 import *

def symbolic_execution():
    # Define the size of the buffer (10 characters)
    BUFFER_SIZE = 10
    
    # Create a symbolic variable for the input
    input_len = Int('input_len')
    
    # Constraint: Input length must be greater than 0
    s = Solver()
    s.add(input_len > 0)
    
    # Add condition for buffer overflow: Input length greater than buffer size
    overflow_condition = input_len > BUFFER_SIZE
    
    # Check if the overflow condition can be satisfied
    s.add(overflow_condition)
    
    # Check if there is a solution (if the condition can be satisfied)
    if s.check() == sat:
        print("Buffer overflow is possible!")
        print("An input longer than", BUFFER_SIZE, "characters can cause an overflow.")
    else:
        print("No overflow detected.")

# Run symbolic execution on the vulnerable code
symbolic_execution()
