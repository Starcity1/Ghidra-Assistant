# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

from os import path, mkdir

from ghidra.program.model.symbol import RefType
from ghidra.util.task import TaskMonitor

current_program = currentProgram

def classify_functions():
    api_functions = []
    system_functions = []
    user_functions = []

    # Get all functions from the program
    functions = current_program.getFunctionManager().getFunctions(True)

    print("Analyzing functions...")
    for function in functions:
        # Print the function we're processing
        # print("Processing function: {} at {}".format(function.getName(), function.getEntryPoint()))

        # Check the symbol associated with this function
        entry_point = function.getEntryPoint()
        symbols = current_program.getSymbolTable().getSymbols(entry_point)

        if not symbols:
            print("No symbols found for function: {}".format(function.getName()))
            continue

        for symbol in symbols:
            symbol_name = symbol.getName()
            source_type = symbol.getSource()

            # Check if the symbol is external (API function)
            if symbol.isExternal():
                api_functions.append(symbol_name)
                # print("API Function: {}".format(symbol_name))

            # Check if the function is imported (likely a system call)
            elif source_type.toString() == "IMPORTED":
                system_functions.append(symbol_name)
                # print("System Function: {}".format(symbol_name))

            # Otherwise, it is a user-defined function
            else:
                user_functions.append(symbol_name)
                # print("User Function: {}".format(symbol_name))

    return api_functions, system_functions, user_functions


# Classify functions into their categories
api_functions, system_functions, user_functions = classify_functions()

# @david Save the results in the Downloads folder. We will be using an absolute path that is os safe
OUT_PATH = "./.out-files/"

if not path.exists(OUT_PATH):
    mkdir(path.join(*OUT_PATH.split('/')))

api_function_path = path.join(*(OUT_PATH + "api_functions.txt").split('/'))
with open(api_function_path, "w") as api_file:
    api_file.write("\n".join(api_functions))

system_functions_path = path.join(*(OUT_PATH + "system_functions.txt").split('/'))
with open(system_functions_path, "w") as sys_file:
    sys_file.write("\n".join(system_functions))

user_functions_path = path.join(*(OUT_PATH + "user_functions.txt").split('/'))
with open(user_functions_path, "w") as user_file:
    user_file.write("\n".join(user_functions))

print("Function classification complete!")

