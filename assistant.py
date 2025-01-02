#
# @author Team 10
# @category util-file
#
import os
from os import environ, path
from re import split
from enum import Enum
import openai as ai
from tools import *
import jpype
from pprint import pprint

#########################################################
#   DO NOT SHARE WITH ANYONE ELSE!!!! THIS IS MY (DAVID) OPEN AI API KEY.
#   I WILL LOSE MONEY IF YOU GUYS TROLL TO CLOSE TO THE SUN LOL
#########################################################
environ['OPENAI_API_KEY'] = None

#########################################################
#   CHANGE TO WHERE YOUR GHIDRA APP IS CURRENTLY LOCATED. SHOULD HAVE SAME FORMAT AS BELOW.
#########################################################
environ['GHIDRA_INSTALL_DIR'] = None
from pyhidra import *
start()

#########################################################
#   MUST BE MODIFIED DEPENDING ON TARGET EXECUTABLE.
#########################################################

TARGET_JPYTHON_SCRIPTS = {
    "classify": r"classify_functions.py",
    "get_definition": r"get_func_declaration.py"
}

class GhidraAssistant:

    # Subclass is simply used for banner.
    class COLOR(Enum):
        RED = "\33[91m"
        BLUE = "\33[94m"
        GREEN = "\033[32m"
        YELLOW = "\033[93m"
        PURPLE = '\033[0;35m'
        CYAN = "\033[36m"
        END = "\033[0m"

    def __init__(self, model="gpt-3.5-turbo"):
        # Start gpt instance, select model, and initialize cli
        self._client = ai.OpenAI(
            api_key=os.getenv('OPENAI_API_KEY')
        )
        self._model = model

        self._init_cli()

    def _init_cli(self):
        self._print_banner()

        quit = False
        while not quit:
            user_input = input("$ ")
            self._run_command(user_input)

    def _run_command(self, user):
        # Parse through user's command
        cmd = split(r'\s+', user.strip())

        match cmd[0]:
            case "exit":
                self._close_cli()

            case "help":
                self._print_commands()

            case "run":
                if len(cmd) != 2:
                    self._print_usage("run")
                else:
                    target_exec = cmd[1]
                    self._run_script(target_exec)

            case "models":
                if len(cmd) < 2:
                    self._print_usage("models")
                else:
                    self._change_model(cmd[1], *cmd[1:])

            case _:
                print("Error unknown command. Use \'help\' command to see all available commands.")

    def _close_cli(self):
        print("Closing instance...")
        exit(0)

    def _change_model(self, models_cmd, *args):
        models = self._client.models.list()
        model_ids = [model.id for model in models.data]

        match models_cmd:
            case "list":
                for id in model_ids:
                    print(id)
            case "change":
                if len(args) != 2:
                    self._print_usage("models")
                if args[1] in model_ids:
                    self._model = args[1]
                    return
                print(f"Error: model {args[1]} is nor recognized. Use \'models list\' to see all available models")
            case _:
                print(f"Error: command not found.")
                self._print_usage("models")

    # More important function. Allows the user to initialize an instance with model.
    def _run_script(self, target: str):

        ########################################
        #   MODEL SPECIFIC TOOL METHODS
        ########################################

        # GPT will use when trying to list all user functions.
        def list_user_symbols(filepath: str):
            # Lists all user symbols analyzed from script.
            user_functions_path = path.join(*filepath.split("/"))
            if not path.exists(user_functions_path):
                return {"error": f"Could not read user functions from executable. (Invalid filepath at {user_functions_path})."}

            try:
                with open(user_functions_path, 'r') as user_func_file:
                    user_functions = [line.strip() for line in user_func_file]

                return {"content": ", ".join(user_functions)}
            except(...):
                return {"error": f"File {user_functions_path} was not opened properly."}

        # GPT will use when being asked upon a specific function from executable.
        def get_code_definition(function_symbol: str):
            # Run Jython script that gets symbol declaration

            # Ensure the target file exists
            if not os.path.exists(target):
                raise FileNotFoundError(f"Target file does not exist: {target}")

            args = [function_symbol]
            java_args = jpype.JArray(jpype.JString)(args)
            run_script(target, TARGET_JPYTHON_SCRIPTS["get_definition"], script_args=java_args)

            out_path = "./.out-files/contents.txt"

            try:
                with open(out_path, 'r') as content_file:
                    function_definition = [line for line in content_file]

                return {"content": "\n".join(function_definition)}
            except(...):
                return {"error": f"Could not read contents of the function."}


        ########################################
        #   AI ASSISTANT CODE
        ########################################

        if not path.exists(target):
            print(f"Error: file \'{target}\' does not exist")
            return

        print("Analyzing executable...")
        run_script(target, TARGET_JPYTHON_SCRIPTS["classify"])

        print("Initializing instance...")

        init_message = message + [{
                "role": "user",
                "content": "I just processed an executable using Ghidra the symbol outputs are "
                           "found in the local file `./.out-files/user_functions.txt`. Process the contents of this file.\n"
            }]
        _ = ai.chat.completions.create(
            model=self._model,
            messages=init_message,
            tools=functions,
            max_tokens=200,
        )

        while True:
            # TODO: Clean temporary txt files.

            prompt = input("> ")
            if prompt.lower() == "quit":
                break

            message.append({
                "role": "user",
                "content": prompt,
            })

            response = ai.chat.completions.create(
                model=self._model,
                messages=message,
                tools=functions,
                max_tokens=400,
            )

            message.pop()

            # print(*response)

            for choice in response.choices:
                if choice.message.tool_calls is not None:
                    func_call = choice.message.tool_calls[0].function
                    if func_call.name == "list_user_symbols":
                        arguments = eval(func_call.arguments)  # Parse the arguments
                        result = list_user_symbols(arguments["file_path"])
                        if "content" in result:
                            result_message = [{
                                "role": "user",
                                "content": "Use the following functions I just got from calling list_user_symbols localy to answer"
                                           "DO NOT CALL any of the tool calls you have."
                                           " any question I have i the future!:\n"
                                           f"{result}"
                            }]
                            response = ai.chat.completions.create(
                                model=self._model,
                                messages=result_message,
                            )
                            end_message = response.choices[0].message.content
                            print(f"{end_message}")
                        elif "error" in result:
                            print(f"{result['error']}")

                    if func_call.name == "get_code_definition":
                        arguments = eval(func_call.arguments)
                        symbol = arguments["function_symbol"]
                        result = get_code_definition(symbol)

                        if "content" in result:
                            result_message = [{
                                "role": "user",
                                "content": "Here is the output from requesting the function definition from "
                                           f"{symbol}. Please use the following output "
                                           f"for any upcoming questions the user may have. "
                                           f"DO NOT CALL get_code_definition again. Please just keep in mind the contents"
                                           f"below:\n"
                                           f"{result['content']}"
                            }]
                            response = ai.chat.completions.create(
                                model=self._model,
                                messages=result_message,
                            )
                            end_message = response.choices[0].message.content if response.choices[0].finish_reason == "stop" else ""
                            print(f"Here are the contents of function {symbol}:\n"
                                  f"{result["content"]}\n"
                                  f"{end_message}")
                        elif "error" in result:
                            print(f"{result['error']}")


                elif choice.finish_reason == "stop":
                    ai_response = choice.message.content
                    print(ai_response)



    ########################################
    #   STATIC METHODS
    ########################################

    @staticmethod
    def _print_commands():
        print(r"""
Ghidra Assistant:
help            Lists all available commands for this assistant.
exit            Closes current instance of assistance.
models          Lists or changes the current GPT model.
run             Runs Executable through Ghidra, then opens GPT's instance 
                that allows user to ask prompts about the analyzed GPT.
        """)

    @staticmethod
    def _print_usage(cmd):
        match cmd:
            case "models":
                print("Usage: models [list, change] [model_name]")
            case "run":
                print("Usage: run [executable]")

    @staticmethod
    def _print_banner():
        banner = r"""
  ________.__    .__    .___                  _____                .__         __                 __   
 /  _____/|  |__ |__| __| _____________      /  _  \   ______ _____|__| ______/  |______    _____/  |_
/   \  ___|  |  \|  |/ __ |\_  __ \__  \    /  /_\  \ /  ___//  ___|  |/  ___\   __\__  \  /    \   __\
\    \_\  |   Y  |  / /_/ | |  | \// __ \_ /    |    \\___ \ \___ \|  |\___ \ |  |  / __ \|   |  |  |  
 \______  |___|  |__\____ | |__|  (____  / \____|__  /____  /____  |__/____  >|__| (____  |___|  |__|  
        \/     \/        \/            \/          \/     \/     \/        \/           \/     \/      """
        print(banner)

if __name__ == "__main__":
    assistant = GhidraAssistant()
