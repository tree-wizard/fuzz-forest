from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz_recon import LangFuzzRecon

#os.environ["OPENAI_API_KEY"] = "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"
#openai.api_key = "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"

lib = 'urllib3'
repo_path = 'saved_repos'
base_prompts_path = "prompts/base-atheris-prompt.py"
sqlitedb = 'langfuzz.db'

libraries2 = { 
    'babel': 'https://github.com/python-babel/babel',
    'twisted': {
        'github': 'https://github.com/twisted/twisted',
        'docs': 'https://docs.twisted.org/en/stable/'
    },
    'scrapy' : 'https://github.com/scrapy/scrapy',
    'flask': 'https://github.com/pallets/flask',
    'tornado': 'https://github.com/tornadoweb/tornado',
    'django': 'https://github.com/django/django',
    'scipy': 'https://github.com/scipy/scipy',
    'numpy': 'https://github.com/numpy/numpy',
    'pytorch': 'https://github.com/pytorch/pytorch',
    'beautifulsoup4': 'https://github.com/wention/BeautifulSoup4',
    'idna': 'https://github.com/kjd/idna',
    'charset_normalizer': 'https://github.com/Ousret/charset_normalizer'
}

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
langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, libraries1, 'python')
# set up the langfuzz main class
langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

# radon_score is optional
#radon_score = ['C', 'D', 'E', 'F']
#priority_funcs = langfuzz.get_radon_functions_from_db("cryptography", radon_score)
#load_functions = langfuzz.get_functions_that_contain_string("cryptography", 'load')
#langfuzz.generate_fuzz_tests("cryptography", load_functions)
#langfuzz.initial_fuzz_analysis("cryptography")
#langfuzz.fix_fuzz_test_code("cryptography")
#langfuzz.check_instrumentation()
#langfuzz.extended_fuzz_analysis("cryptography", 7500, exception=False)

#func_list = ['parsemsg', 'parseIdList', 'load_pkcs12', 'serialize_key_and_certificates']
#langfuzz.extended_fuzz_analysis_by_filenames(func_list, time=600)


## First pass
#print("Generating fuzz tests")
#for library_name in libraries1.keys():
#    print(library_name)   
#    #print("Getting functions that contain string 'parse'")
#    parse_functions = langfuzz.get_functions_that_contain_string(library_name, 'parse')
#    format_functions = langfuzz.get_functions_that_contain_string(library_name, 'format')
#    load_functions = langfuzz.get_functions_that_contain_string(library_name, 'load')
#    encode_functions = langfuzz.get_functions_that_contain_string(library_name, 'encode')
#    decode_functions = langfuzz.get_functions_that_contain_string(library_name, 'decode')
#    serialze_functions = langfuzz.get_functions_that_contain_string(library_name, 'serialize')
#    langfuzz.generate_fuzz_tests(library_name, parse_functions)
#    langfuzz.generate_fuzz_tests(library_name, format_functions)
#    langfuzz.generate_fuzz_tests(library_name, load_functions)
#    langfuzz.generate_fuzz_tests(library_name, encode_functions)
#    langfuzz.generate_fuzz_tests(library_name, decode_functions)
#    langfuzz.generate_fuzz_tests(library_name, serialze_functions)

# Initial fuzz pass
#print("Running initial fuzz analysis")
#for library_name in libraries1.keys():
#    print(library_name)
#    langfuzz.initial_fuzz_analysis(library_name) 
#
## Fixing non running fuzz tests
#print("Fixing fuzz test code")
#for library_name in libraries1.keys():
#    print(library_name)
#    langfuzz.fix_fuzz_test_code(library_name)

# Running extended fuzz analysis
print("Running extended fuzz analysis")
for library_name in libraries1.keys():
    print(library_name)
    langfuzz.check_instrumentation()
    langfuzz.extended_fuzz_analysis(library_name, 2000, exception=False, instrumented=True)
"""
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


