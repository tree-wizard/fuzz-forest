from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz_recon import LangFuzzRecon

repo_path = 'saved_repos'
base_prompts_path = "prompts/base-atheris-prompt.py"
sqlitedb = 'langfuzz-lib2-gpt4.db'

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
    #'pytorch': 'https://github.com/pytorch/pytorch',
    'pandas': 'https://github.com/pandas-dev/pandas',
    'ansible': 'https://github.com/ansible/ansible',
    'homeassistant': 'https://github.com/home-assistant/core',
    'transformers': 'https://github.com/huggingface/transformers',
    'beautifulsoup4': 'https://github.com/wention/BeautifulSoup4',
    'idna': 'https://github.com/kjd/idna',
    'charset_normalizer': 'https://github.com/Ousret/charset_normalizer'
}

# Recon to create the database with fuzzing data.
#langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, libraries2, 'python')
# set up the langfuzz main class
langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

'''
# In this approach we are going to individually desribe the fuzz tests we want to generate
fuzzer_count = 0
radon_score = ['D', 'E', 'F']
print("Generating Babel fuzz tests")
library_name = 'babel'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'load'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'encod'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Twisted fuzz tests")
library_name = 'twisted'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'load'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Scrapy fuzz tests")
library_name = 'scrapy'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'load'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Flask fuzz tests")
library_name = 'flask'
function_list = []
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['C', 'D', 'E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Tornado fuzz tests")
library_name = 'tornado'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'load'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'encode'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Django fuzz tests")
library_name = 'django'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'serial'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Scipy fuzz tests")
library_name = 'scipy'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Numpy fuzz tests")
library_name = 'numpy'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

#print("Generating pytorch fuzz tests")
#library_name = 'pytorch'
#function_list = []
#function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
#function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
#function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'serial'))
#print(len(function_list))
#fuzzer_count += len(function_list)
#langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating Pandas fuzz tests")
library_name = 'pandas'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generarating Ansible fuzz tests")
library_name = 'ansible'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generarting homeassistant fuzz tests")
library_name = 'homeassistant'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating transformers fuzz tests")
library_name = 'transformers'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'parse'))
#function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'serial'))
#function_list.extend(langfuzz.get_radon_functions_from_db(library_name, ['E', 'F']))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating idna fuzz tests")
library_name = 'idna'
function_list = []
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'decode'))
function_list.extend(langfuzz.get_functions_that_contain_string(library_name, 'serial'))
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generating charset_normalizer fuzz tests")
library_name = 'charset_normalizer'
function_list = []
function_list.extend(langfuzz.get_radon_functions_from_db(library_name, radon_score))
print(len(function_list))
fuzzer_count += len(function_list)
langfuzz.generate_fuzz_tests(library_name, function_list)

print("Generated " + str(fuzzer_count) + " fuzzers.")

print("Running initial fuzz analysis")
for library_name in libraries2.keys():
    print(library_name)
    langfuzz.initial_fuzz_analysis(library_name)

# created 338 fuzz tests
# 111 run = True
# cost of $22.17
'''
langfuzz.check_instrumentation()
print("Running extended fuzz analysis")
for library_name in libraries2.keys():
    print(library_name)
    langfuzz.extended_fuzz_analysis(library_name, time=750)


""" 
print("Fixing fuzz test code")
for library_name in libraries2.keys():
    print(library_name)
    langfuzz.fix_fuzz_test_code(library_name)

# max attempts of 5
# 'fixed' x of x to run status
# x have exception=True
# $.x
# xx instrumented

print("Running extended fuzz analysis")
for library_name in libraries.keys():
    print(library_name)
    langfuzz.check_instrumentation()
    langfuzz.extended_fuzz_analysis(library_name, time=750)
"""
