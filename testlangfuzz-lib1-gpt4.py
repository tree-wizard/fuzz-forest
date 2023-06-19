from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz_recon import LangFuzzRecon

repo_path = 'saved_repos'
base_prompts_path = "prompts/base-atheris-prompt.py"
sqlitedb = 'langfuzz-lib1-gpt4.db'

libraries1 = {
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
    'sqlalchemy': 'https://github.com/sqlalchemy/sqlalchemy',
    'PIL': 'https://github.com/python-pillow/Pillow',
    'yaml': 'https://github.com/yaml/pyyaml',
    'cryptography': {
        'github': 'https://github.com/pyca/cryptography',
        'docs': 'https://cryptography.io/en/latest/'
    },
    'botocore': 'https://github.com/boto/botocore',
    'boto3': 'https://github.com/boto/boto3',
    'rq': 'https://github.com/rq/rq'}

# Recon to create the database with fuzzing data.
#langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, libraries1, 'python')
# set up the langfuzz main class
langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

# radon_score is optional
radon_score = ['D', 'E', 'F']


print("Generating fuzz tests")
for library_name in libraries1.keys():
    print(library_name)
    complex_functions = langfuzz.get_radon_functions_from_db(library_name, radon_score)
    parse_functions = langfuzz.get_functions_that_contain_string(library_name, 'parse')    
    format_functions = langfuzz.get_functions_that_contain_string(library_name, 'format')
    encode_functions = langfuzz.get_functions_that_contain_string(library_name, 'encode')
    decode_functions = langfuzz.get_functions_that_contain_string(library_name, 'decode')
    serialze_functions = langfuzz.get_functions_that_contain_string(library_name, 'serialize')
    langfuzz.generate_fuzz_tests(library_name, parse_functions)
    langfuzz.generate_fuzz_tests(library_name, format_functions)
    langfuzz.generate_fuzz_tests(library_name, encode_functions)
    langfuzz.generate_fuzz_tests(library_name, decode_functions)
    langfuzz.generate_fuzz_tests(library_name, serialze_functions)

# Initial fuzz pass
print("Running initial fuzz analysis")
for library_name in libraries1.keys():
    print(library_name)
    langfuzz.initial_fuzz_analysis(library_name) 

# created xx fuzz tests
# xx run
# cost of $.xx
    
'''
## Fixing non running fuzz tests
print("Fixing fuzz test code")
for library_name in libraries1.keys():
    print(library_name)
    langfuzz.fix_fuzz_test_code(library_name)
    
# max attempts of 5
# 'fixed' xx of xx to run status
# xx have exception=True
# $.xx
# xx instrumented




# Running extended fuzz analysis
print("Running extended fuzz analysis")
for library_name in libraries1.keys():
    print(library_name)
    langfuzz.check_instrumentation()
    langfuzz.extended_fuzz_analysis(library_name, 100, exception=False, instrumented=True) # deprecated=False)
'''


"""


# Triage Pass
#for library_name in http_libs.keys():
#    print(library_name)
#    langfuzz.analyze_fuzz_coverage(library_name)
#    langfuzz.triage_fuzz_crashes(library_name)]
"""
