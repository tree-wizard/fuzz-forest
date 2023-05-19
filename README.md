# LLM Fuzz (previously fuzzforest)

LLM Fuzz is an experimental tool that leverages large language models (LLMs) like OpenAI's GPT models for automating fuzz testing of Python codebases. It is designed to streamline the process of writing, fixing, and triaging fuzz tests, thus saving developers from the intricacies of deep diving into the codebase.

Read more about the motivation, implementation, and research insights in the blog post:
[LLM Fuzz Part 1](https://infiniteforest.org/LLM+Fuzz/LLM+Fuzz+Part+1)

## How to Use

## Testcase
```
from langfuzz.langfuzz import LangFuzz
from langfuzz.langfuzz_recon import LangFuzzRecon

repo_path = 'saved_repos'
base_prompts_path = "prompts/base-atheris-prompt.py"
sqlitedb = 'langfuzz-libs.db'

libraries2 = { 
    'babel': 'https://github.com/python-babel/babel',
    'twisted': {
        'github': 'https://github.com/twisted/twisted',
        'docs': 'https://docs.twisted.org/en/stable/'
    },
    'scrapy' : 'https://github.com/scrapy/scrapy',
    'flask': 'https://github.com/pallets/flask',
    
}

langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

fuzzer_count = 0
radon_score = ['D', 'E', 'F']
print("Generating Babel fuzz tests")
library_name = 'babel'
function_list = []

langfuzz.generate_fuzz_tests(library_name, function_list)

print("Running initial fuzz analysis")
for library_name in libraries2.keys():
    print(library_name)
    langfuzz.initial_fuzz_analysis(library_name)

print("Fixing fuzz test code")
for library_name in libraries2.keys():
    print(library_name)
    langfuzz.fix_fuzz_test_code(library_name)
```
## Pulling functions:
llmfuzz.get_fuzz_tests_by_filenames(f)


## Fuzzing functions

parse_function_list = langfuzz.get_functions_that_contain_string(library_name, 'parse')
llmfuzz.fuzz_functions_list(parse_function_list, time=20000)

file_functions = llmfuzz.get_functions_by_filename(library_name, 'ssl.py')

# Roadmap

This project is still in the active development stage. Here is a brief overview of our roadmap:

Improving Test Harness Generation: As a first step, we are focusing on creating a robust mechanism to generate a high-quality fuzz test harness automatically.

Integrating with More Fuzzing Libraries: We plan to support a broader range of fuzzing libraries to provide more flexibility to the users.

Scaling to Large Codebases: Currently, the tool works best on small to medium-sized codebases. We are working on scaling it to larger codebases with complex architectures.

Automating Triage Process: We aim to automate the triage process as much as possible, reducing the manual work required to analyze fuzzing results.

Codebase Coverage Metrics: We plan to include features to automatically calculate and report the coverage of the codebase by the generated fuzz tests.


# Trophy Case
