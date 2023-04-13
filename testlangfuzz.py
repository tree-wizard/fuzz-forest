from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz import get_fuzz_tests_from_db
from langfuzz.langfuzz import GeneratedFile, Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session
import os
import openai
import sys
import subprocess
from llm_agent import Agent, ChatLLM
from llm_agent.tools.base import ToolInterface
from llm_agent.tools.python_repl import PythonREPLTool, PythonREPLFuzzTool
from llm_agent.tools.search import SerpAPITool 
from langfuzz.langfuzz_recon import LangFuzzRecon

#os.environ["OPENAI_API_KEY"] = "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"
#openai.api_key = "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"

lib = 'urllib3'
repo_path = 'saved_repos'
base_prompts_path = "prompts/base-atheris-prompt.py"
sqlitedb = 'langfuzz.db'

http_libs = {
    'urllib3': {
        'github': 'https://github.com/urllib3/urllib3',
        'docs': 'https://urllib3.readthedocs.io/en/stable/'
    },
    'aiohttp': 'https://github.com/aio-libs/aiohttp/',
    'twisted': {
        'github': 'https://github.com/twisted/twisted',
        'docs': 'https://docs.twisted.org/en/stable/'
 }}

# Recon to create the database with fuzzing data.
langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, http_libs, 'python')

langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

# radon_score is optional, if you don't pass it, it will pull all the functions
#radon_score = ['C', 'D', 'E', 'F']
#priority_funcs = langfuzz.get_radon_functions_from_db('urllib3', radon_score)
priority_funcs = ['create_urllib3_context', 'ssl_wrap_socket','match_hostname', 'parse_url']

# Creates the fuzzers and saves in db
langfuzz.generate_fuzz_tests(lib, priority_funcs)
langfuzz.initial_fuzz_analysis(lib)
#langfuzz.extended_fuzz_analysis(lib)





python = """for fizzbuzz in range(51):
if fizzbuzz % 3 == 0 and fizzbuzz % 5 == 0:
print("fizzbuzz")
continue
elif fizzbuz % 3 == 0:
print("fizz")
continue
elif fizzbuzz % 5 == 0:
print("buzz")
continue
print(fizzbuzz)
"""
code2 = """
import atheris
import sys

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeInt(10)
    b = fdp.ConsumeInt(10)
    try:
        add(a, b)
    except:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
"""

"""
fuzz_files = get_fuzz_tests_from_db(sqlitedb, lib)
print('debug')
for file in fuzz_files:
    id, file_name, function_name, contents = file
    print("+------------------------------------+")
    print(function_name)
"""




