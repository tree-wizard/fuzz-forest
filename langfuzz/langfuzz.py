import os
import openai
import re
import subprocess
import time
from typing import Tuple

from .langfuzzDB import Database
from .utils import run_atheris_fuzzer, num_tokens_from_string

class LangFuzz:
    def __init__(self, sqlitedb, language, base_prompt_path):
        self.db = Database(sqlitedb)
        self.sqlitedb = sqlitedb
        self.language = language
        self.base_prompt_path = base_prompt_path #replace with find_base_prompt_path()

    def find_base_prompt_path(self):
        if self.language == "python":
            return os.path.join('prompts', 'base-atheris-prompt.py')
        else:
            raise Exception(f"Language {self.language} not supported.")

    def generate_fuzz_code(self, prompt):
        response = openai.ChatCompletion.create(
            model='gpt-4',
            messages=[
                {"role": "system", "content": prompt}],
            max_tokens=1550,
            temperature=0.6,
        )
        return response["choices"][0]["message"]["content"]

    def save_fuzz_test_to_db(self, library_name, function_name, fuzz_test_code):
        file_name = 'fuzz_' + function_name + '.py'
        tokens = num_tokens_from_string(fuzz_test_code)
        with self.db as db:
            db.save_fuzz_test_to_db(library_name, function_name, file_name, fuzz_test_code, tokens)

    def update_fuzz_test_in_db(self, id, runs=None, run_output=None, coverage=None, exception=None, crash=None, contents=None, refactored=None, instrumented=None):
        with self.db as db:
            db.update_fuzz_test_in_db(id, runs, run_output, coverage, exception, crash, contents, refactored, instrumented)

    def get_existing_fuzz_file_data(self, library_name):
        with self.db as db:
            return db.get_existing_fuzz_file_data(library_name)
        
    def get_generated_functions_that_contain_string_in_contents(self, search_string):
        with self.db as db:
            return db.get_generated_functions_that_contain_string_in_contents(search_string)
    
    def get_functions_that_contain_string(self, library_name, search_string):
        with self.db as db:
            result = db.get_functions_that_contain_string(library_name, search_string)
        # Filter out None values and extract function names from the tuples
        function_names = [func[0] for func in result if func[0] is not None]
        return function_names
    
    def get_lib_fuzz_tests_from_db(self, library_name, runs=None, exception=None, refactored=None, instrumented=None):
        with self.db as db:
            return db.get_lib_fuzz_tests_from_db(library_name, runs, exception, refactored, instrumented)

    def get_radon_functions_from_db(self, lib_name, score=None):
        with self.db as db:
            return db.get_radon_functions_from_db(lib_name, score)

    def check_instrumentation(self):
        functions = self.get_generated_functions_that_contain_string_in_contents("atheris.instrument_all()")
        for function in functions:
            print(function.function_name)
            #mark as instrumented
            self.update_fuzz_test_in_db(function.id, instrumented=True)

    def create_prompt(self, base_template, fuzzer_context, library_name, function_name, function_code):
       if self.language == 'python':
           directive = f"Return ONLY valid and properly formatted Python code. Do NOT include any comments, explanations or notes. Import the {library_name} and write an atheris fuzz test for the {function_name} function in {library_name}:\n"
       else:
           directive = "Write a fuzz test for the following function:\n"

       exception_check = "Review function source and make sure to catch and ignore any EXPECTED exceptions that may arise from passing invalid input to the tested function." 
       
       prompt = base_template + fuzzer_context + directive + "This is the source code for" + function_name + ":" + function_code + exception_check
       num_tokens = num_tokens_from_string(prompt)

       if num_tokens < 2500:
           return prompt

       else:
        prompt = base_template + directive + "This is the source code for" + function_name + ":" + function_code + exception_check
        num_tokens = num_tokens_from_string(prompt)
        
        if num_tokens <= 2500:
            return prompt

       prompt = base_template + fuzzer_context + directive
       num_tokens = num_tokens_from_string(prompt)

       if num_tokens <= 2400:
           return prompt

       prompt = base_template + directive

       return prompt

    def fix_code(self, code: str, output: str) -> str:
        # Use OpenAI GPT to generate a fixed version of the code
        # Modify the code to fix the problem
        # Return the updated code
        prompt = (
        f"Please rewrite the following code to fix any issues or errors:\n\n"
        f"---Code Starts---\n"
        f"{code}\n"
        f"---Code Ends---\n\n"
        f"Output: {output}\n\n"
        f"IMPORTANT: Return only valid and properly formatted Python code. Do NOT include any comments, explanations or notes on the changes made."
    )
        response = openai.ChatCompletion.create(
                model='gpt-3.5-turbo',
                messages=[
                    {"role": "system", "content": prompt}],
                max_tokens=1550,
                temperature=0.6,
            )
        return response["choices"][0]["message"]["content"]

    def fix_fuzz_test(self, function_code, output) -> Tuple[str, str, bool]:
        successful_run = 'Done 2 runs'
        max_attempts = 10
        updated_code = function_code

        for _ in range(max_attempts):
            print(f'fixing code, attempt {_}')
            updated_code = self.fix_code(updated_code, output)
            new_output = run_atheris_fuzzer(updated_code)

            if successful_run in new_output:
                print('fixed')
                return updated_code, new_output, True
            else:
                output = new_output
                time.sleep(1)
        return updated_code, output, False

    def fix_fuzz_test_code(self, library_name):
        fuzz_functions = self.get_lib_fuzz_tests_from_db(library_name, runs=False)
        for function in fuzz_functions:
            print("Fixing fuzz test code for", function.function_name)
            updated_code, output, runs = self.fix_fuzz_test(function.contents, function.run_output)
            #function to fix fuzz test code, returns fixed_code, run status, and output
            if runs == True:
                self.update_fuzz_test_in_db(function.id, runs=True, run_output=str(output), contents=updated_code, refactored=True)
            else:
                self.update_fuzz_test_in_db(function.id, runs=False, run_output=str(output), contents=updated_code, refactored=True) 

    def run_fuzzer(self, command, timeout):
        try:
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True, timeout=timeout)
            crash = False
        except subprocess.CalledProcessError as e:
            output = e.output
            crash = True
        except subprocess.TimeoutExpired:
            output = e.output.decode()
            output += "Fuzzer Timeout"
            crash = False

        return output, crash

    def parse_coverage(self, output):
        cov_pattern = re.compile(r'cov:\s+(\d+)')
        cov_matches = cov_pattern.findall(output)
        if cov_matches:
            cov = int(cov_matches[-1])
        else:
            cov = None

        return cov

    def extended_fuzz_analysis(self, library_name, time=20000, refactored=None, instrumented=None):
        generated_files_path = os.path.join('saved_repos', 'generated_files', 'fuzz')
        os.makedirs(generated_files_path, exist_ok=True)

        fuzz_functions = self.get_lib_fuzz_tests_from_db(library_name, runs=True, refactored=refactored, instrumented=instrumented)

        for function in fuzz_functions:
            function_path = os.path.join(generated_files_path, function.function_name)
            os.makedirs(function_path, exist_ok=True)
            print(function.contents)
            fuzzer_file_path = os.path.join(function_path, function.file_name)

            with open(fuzzer_file_path, 'w') as fuzzer_file:
                fuzzer_file.write(function.contents)

            command = f'python {fuzzer_file_path} -max_total_time={time}'
            timeout = time + 100  # add 2 minute timeout to catch hangs

            output, crash = self.run_fuzzer(command, timeout)
            exception = 'exception' in output.lower()
            cov = self.parse_coverage(output)
            print(output)
            self.update_fuzz_test_in_db(function.id, run_output=output, coverage=cov, exception=exception, crash=crash)

    def initial_fuzz_analysis(self, library):
        fuzz_functions = self.get_lib_fuzz_tests_from_db(library_name=library, runs=False, exception=False)
        print(len(fuzz_functions))
        for function in fuzz_functions:
            print(function.function_name)
            output = run_atheris_fuzzer(function.contents)

            if 'Done 2 runs' in output:
                self.update_fuzz_test_in_db(function.id, runs=True, run_output=output)
            elif 'Exception' in output:
                self.update_fuzz_test_in_db(function.id, runs=False, run_output=output, exception=True)
            else:
                self.update_fuzz_test_in_db(function.id, runs=False, run_output=output)

    def add_fuzz_files_to_prompt(self, file_data):
        fuzz_prompt_context = ''
        for function in file_data:
            fuzz_prompt_context += f"Valid example fuzzer for {function.function_name}:\n{function.contents}\n"
        return fuzz_prompt_context
    
    def generate_fuzz_tests(self, library_name, function_list=None):
        base_template = open(self.base_prompt_path, "r").read()
        fuzz_file_data = self.get_existing_fuzz_file_data(library_name)
        fuzzer_context = self.add_fuzz_files_to_prompt(fuzz_file_data)
        with self.db as db:
            functions = db.get_functions_from_db(library_name, function_list)
                # Above was setup, below we create the full prompt, generate the fuzz test, and save it to the db
        for function in functions:
            complete_prompt = self.create_prompt(base_template, fuzzer_context, library_name, function.function_name, function.contents)
            if not self.db.generated_file_exists(library_name, function.function_name):
                fuzz_test_code = self.generate_fuzz_code(complete_prompt)
                #print("=" * 50)
                print(function.function_name)
                #print(fuzz_test_code)
                self.save_fuzz_test_to_db(library_name, function.function_name, fuzz_test_code)

if __name__ == "__main__":
    http_libs = {
        'urllib3': {
            'github': 'https://github.com/urllib3/urllib3',
            'docs': 'https://urllib3.readthedocs.io/en/stable/'
    } }

    # Initialize LangFuzz object
    langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

    # This defines the score of radon complexity to pull from the database
    # A and B are the highest scores, E and F are the lowest scores
    radon_score = ['C', 'D', 'E', 'F']
    # radon_score is optional, if you don't pass it, it will pull all the functions
    priority_funcs = LangFuzz.get_radon_functions_from_db('urllib3', radon_score)
    langfuzz.generate_fuzz_tests('urllib3', priority_funcs)