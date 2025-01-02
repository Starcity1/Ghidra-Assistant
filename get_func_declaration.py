# TODO write a description for this script
# @author
# @category _NEW_
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

from os import path, mkdir
import sys

## Import necessary Ghidra modules
from ghidra.program.model.symbol import Symbol, SymbolType
from ghidra.program.model.listing import Function, CodeUnit
from ghidra.program.model.address import Address
from ghidra.util.exception import CancelledException
from ghidra.program.model.address import Address
from ghidra.app.decompiler import DecompInterface

current_program = currentProgram


# Function to print the full declaration and contents of a function
OUT_PATH = "./.out-files/"

def print_function_declaration_and_contents(function_symbol):
    # Get the function from the symbol
    out_file = open(OUT_PATH + "contents.txt", 'w')
    function = getFunctionAt(function_symbol.getAddress())
    if function is None:
        print("Sorry, but the function was not found at the given symbol address.")
        return

    # Print the function declaration (name, signature, return type, parameters)
    out_file.write("Function Declaration:\n")
    out_file.write("Name: {}\n".format(function.getName()))
    out_file.write("Signature: {}\n".format(function.getSignature()))
    out_file.write("Return Type: {}\n".format(function.getReturnType()))
    out_file.write("Parameter Count: {}\n".format(function.getParameterCount()))

    # Print parameter types and names
    for i in range(function.getParameterCount()):
        param = function.getParameter(i)
        out_file.write("Param {}: {} - {}\t".format(i, param.getDataType(), param.getName()))
    out_file.write("\n")

    decompiler = DecompInterface()
    decompiler.openProgram(current_program)

    # Decompile the function
    decompiled = decompiler.decompileFunction(function, 30, None)  # 30 is the timeout in seconds

    if decompiled is None:
        out_file.write("Decompilation failed.")
        return

    # Get and print the decompiled text
    decompiled_text = decompiled.getDecompiledFunction().getC()
    out_file.write(decompiled_text)

    out_file.close()


# EXAMPLE:
# if len(argv) < 4:
#     raise RuntimeError("Invalid Usage")

try:
    function_name = sys.argv[1]  # Replace with the actual function name
except(...):
    raise RuntimeError("Not enough parameters!!!")

symbol_manager = current_program.getSymbolTable()

if not path.exists(OUT_PATH):
    mkdir(path.join(*OUT_PATH.split('/')))

# Retrieve all symbols matching the function name
symbols_iterator = symbol_manager.getSymbols(function_name)

# Find the first symbol matching the name (iterator cannot be indexed directly)
symbol = None
for user_symbol in symbols_iterator:
    if user_symbol.getName() == function_name:
        symbol = user_symbol
        break
if symbol:
    # Use the symbol's address to retrieve user symbols (since getUserSymbols() needs an address)
    user_symbols = symbol_manager.getUserSymbols(symbol.getAddress())

    # Find the function symbol from user symbols
    function_symbol = None
    for user_symbol in user_symbols:
        if user_symbol.getSymbolType() == SymbolType.FUNCTION:
            function_symbol = user_symbol
            break

    if function_symbol:
        print_function_declaration_and_contents(function_symbol)
    else:
        print("No function symbol found at the address of '{}'.".format(function_name))
else:
    print("No symbol found with the name '{}'.".format(function_name))
