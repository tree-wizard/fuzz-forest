from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz_recon import LangFuzzRecon
from langfuzz.langfuzzDB import Database
from langfuzz.langfuzzDB import GeneratedFile, Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session


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

libs = {
    'urllib3': {
        'github': 'https://github.com/urllib3/urllib3',
        'docs': 'https://urllib3.readthedocs.io/en/stable/'
    },
    'requests': {
        'github': 'https://github.com/psf/requests',
        'docs': 'https://requests.readthedocs.io/en/latest/'
    },
    'aiohttp': {
        'github': 'https://github.com/aio-libs/aiohttp/',
        'docs': 'https://docs.aiohttp.org/en/stable/'
    },
    'twisted': {
        'github': 'https://github.com/twisted/twisted',
        'docs': 'https://docs.twisted.org/en/stable/'
    },
    'sqlalchemy': 'https://github.com/sqlalchemy/sqlalchemy',
    'PIL': 'https://github.com/python-pillow/Pillow',
    'babel': 'https://github.com/python-babel/babel',
    'yaml': 'https://github.com/yaml/pyyaml',
    'cryptography': {
        'github': 'https://github.com/pyca/cryptography',
        'docs': 'https://cryptography.io/en/latest/'
    },
    'botocore': 'https://github.com/boto/botocore',
    'boto3': 'https://github.com/boto/boto3',
    'rq': 'https://github.com/rq/rq'}

# radon_score is optional, if you don't pass it, it will pull all the functions

#priority_funcs = langfuzz.get_radon_functions_from_db('urllib3', radon_score)
# Creates the fuzzers and saves in db
#langfuzz.generate_fuzz_tests(lib, priority_funcs)
#langfuzz.initial_fuzz_analysis(lib)
#langfuzz.extended_fuzz_analysis(lib)

# Recon to create the database with fuzzing data.
langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, http_libs, 'python')
# set up the langfuzz main class
langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)
# radon_score is optional, if you don't pass it, it will pull all the functions
radon_score = ['C', 'D', 'E', 'F']


# First pass
for library_name in http_libs.keys():
    print(library_name)
    #priority_funcs = langfuzz.get_radon_functions_from_db(library_name, radon_score)
    #parse_functions = langfuzz.get_functions_that_contain_string(library_name, 'parse')
    #langfuzz.generate_fuzz_tests(library_name, priority_funcs)
    #langfuzz.initial_fuzz_analysis(library_name)

    #langfuzz.fix_fuzz_tests(library_name)

# Second pass
#for library_name in libs.keys():
#    print(library_name)
#    langfuzz.fix_fuzz_tests(library_name) 
#    langfuzz.extended_fuzz_analysis(library_name, 200)



# Analysis Pass
#for library_name in libs.keys():
#    print(library_name)
#    langfuzz.analyze_fuzz_coverage(library_name)
#     langfuzz.triage_fuzz_crashes(library_name) 

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




