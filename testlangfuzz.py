from langfuzz.langfuzz import LangFuzz
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
    'cryptography': {
        'github': 'https://github.com/pyca/cryptography',
        'docs': 'https://cryptography.io/en/latest/'
    }
}

libraries = {
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
   # 'babel': 'https://github.com/python-babel/babel',
    'yaml': 'https://github.com/yaml/pyyaml',
    'cryptography': {
        'github': 'https://github.com/pyca/cryptography',
        'docs': 'https://cryptography.io/en/latest/'
    },
    'botocore': 'https://github.com/boto/botocore',
    'boto3': 'https://github.com/boto/boto3',
    'rq': 'https://github.com/rq/rq'}

# Recon to create the database with fuzzing data.
langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, http_libs, 'python')
# set up the langfuzz main class
langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

# radon_score is optional
#radon_score = ['C', 'D', 'E', 'F']
#priority_funcs = langfuzz.get_radon_functions_from_db("cryptography", radon_score)
load_functions = langfuzz.get_functions_that_contain_string("cryptography", 'load')
langfuzz.generate_fuzz_tests("cryptography", load_functions)
langfuzz.initial_fuzz_analysis("cryptography")
langfuzz.fix_fuzz_test_code("cryptography")
langfuzz.check_instrumentation()
langfuzz.extended_fuzz_analysis("cryptography", 1200, instrumented=True)

"""
# First pass
for library_name in http_libs.keys():
    print(library_name)   
    print("Getting functions that contain string 'parse'")
    parse_functions = langfuzz.get_functions_that_contain_string(library_name, 'parse')
    print("Generating fuzz tests")
    langfuzz.generate_fuzz_tests(library_name, parse_functions)

# Initial fuzz pass
for library_name in http_libs.keys():
    print(library_name)
    print("Running initial fuzz analysis")
    langfuzz.initial_fuzz_analysis(library_name) 

# Fixing non running fuzz tests
for library_name in http_libs.keys():
    print("Fixing fuzz test code")
    langfuzz.fix_fuzz_test_code(library_name)


# Running extended fuzz analysis
for library_name in http_libs.keys():
    print(library_name)
    langfuzz.extended_fuzz_analysis(library_name, 200)

# extended fuzz analysis pass on instrumented code
for library_name in http_libs.keys():
    print(library_name)
    langfuzz.check_instrumentation()
    langfuzz.extended_fuzz_analysis(library_name, 1200, instrumented=True)

# Triage Pass
#for library_name in http_libs.keys():
#    print(library_name)
#    langfuzz.analyze_fuzz_coverage(library_name)
#    langfuzz.triage_fuzz_crashes(library_name)]
"""


