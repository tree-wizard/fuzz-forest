# LLM Fuzz (previously fuzzforest)

Check out my introductory blog post:
[LLM Fuzz Part 1](https://infiniteforest.org/LLM+Fuzz/LLM+Fuzz+Part+1)

## How to Use


## Pulling functions:
llmfuzz.get_fuzz_tests_by_filenames(f)


## Fuzzing functions



parse_function_list = langfuzz.get_functions_that_contain_string(library_name, 'parse')
llmfuzz.fuzz_functions_list(parse_function_list, time=20000)

file_functions = llmfuzz.get_functions_by_filename(library_name, 'ssl.py')


# Trophy Case