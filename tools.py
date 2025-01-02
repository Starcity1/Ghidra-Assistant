# The following file just contains tools declarations for the GPT model to be used.

functions = [
    {
        "type": "function",
        "function": {
            "name": "list_user_symbols",
            "description": "Get a list of all user functions found within the decompiled executable. "
                           "Call this function whenever the user asks you to list specifically all or some user functions. "
                           "Assume that the decompilation process has been done already."
                           "If no filepath is given by the user. use the default filepath `./.out-files/user_functions.txt`."
                           " DO NOT call this function if the user is attempting to gain information of that specific function."
                           "That is, do not call this function if the user asks you to explain the contents of a given function."
                           "For that use the get_code_definition tool."
                           "Instead, attempt to explain what the function might do without calling this tool function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "file_path": {"type": "string", "description": "The path to the temporary file"}
                },
                "required": ["file_path"]
        }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_code_definition",
            "description": "Returns the content of a specified function found at ./.out-files/user_functions.txt."
                           "This function assumes that the function `list_user_symbols` has been already called. If not,"
                           "tell the user that you do not know the contents of the symbol yet, and encourage the user to first"
                           "call `list_user_symbols` first. At the end print both the function's declaration as well as a two to three sentence"
                           "description about the contents of this function. Note that the you will have access to the entire "
                           "contents of the function.",
            "parameters": {
                "type": "object",
                "properties": {
                    "function_symbol": {"type": "string", "description": "The name of the function we are trying to analyze."}
                },
                "required": ["file_path"]
        }
        }
    },
]

message = [
    {
        "role": "system",
        "content": "You are a helpful reverse engineering assistant with access to Ghidra tools. "
                   "Use the supplied tools to help the user. The tool functions will return with their output."
                   "So, refrain yourself to use the tools as much as possible. Only use them if told to list or print"
                   "the contents of the binary."
    },
]
