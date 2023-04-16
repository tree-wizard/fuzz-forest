import os
import openai
import importlib
import importlib.util
import re
import subprocess

from sqlalchemy.orm import Session

from .langfuzz_recon import LangFuzzRecon
from .langfuzzDB import Database, GeneratedFile, LibraryFile, Library, get_engine
from .utils import run_initial_atheris_fuzzer, num_tokens_from_string, get_fuzz_tests_from_db

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
            model='gpt-3.5-turbo',
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

    def update_fuzz_test_in_db(self, id, runs=None, run_output=None, coverage=None, exception=None, crash=None):
        with self.db as db:
            db.update_fuzz_test_in_db(id, runs, run_output, coverage, exception, crash)

    def get_existing_fuzz_file_data(self, library_name):
        with self.db as db:
            return db.get_existing_fuzz_file_data(library_name)
        
    def get_functions_that_contain_string(self, library_name, search_string):
        with self.db as db:
            return db.get_functions_that_contain_string(library_name, search_string)
        
    def create_prompt(self, base_template, fuzzer_context, library_name, function_name, function_code):
       if self.language == 'python':
           directive = "Return only valid, formated python code, no text. Write an atheris fuzz test for the following function:\n"
       else:
           directive = "Write a fuzz test for the following function:\n"

       prompt = base_template + fuzzer_context + directive + function_code
       num_tokens = num_tokens_from_string(prompt)

       if num_tokens <= 2400:
           return prompt

       else:
        prompt = base_template + directive + function_code
        num_tokens = num_tokens_from_string(prompt)
        
        if num_tokens <= 2400:
            return prompt

       prompt = base_template + fuzzer_context + directive + library_name + " " + function_name
       num_tokens = num_tokens_from_string(prompt)

       if num_tokens <= 2400:
           return prompt

       prompt = base_template + directive + library_name + "." + function_name

       return prompt

    def extended_fuzz_analysis(self, library_name, time=20000):
        generated_files_path = os.path.join('saved_repos', 'generated_files', 'fuzz')
        os.makedirs(generated_files_path, exist_ok=True)

        fuzz_files = get_fuzz_tests_from_db(self.sqlitedb, library_name, runs=True)

        for file in fuzz_files:
            id, file_name, function_name, contents = file
            function_path = os.path.join(generated_files_path, function_name)
            os.makedirs(function_path, exist_ok=True)
            print(contents)
            fuzzer_file_path = os.path.join(function_path, file_name)

            with open(fuzzer_file_path, 'w') as fuzzer_file:
                fuzzer_file.write(contents)

            command = f'python {fuzzer_file_path} -max_total_time={time}'
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                crash = False
            except subprocess.CalledProcessError as e:
                output = e.output
                crash = True

            exception = 'exception' in output.lower()

            cov_pattern = re.compile(r'cov:\s+(\d+)')
            cov_matches = cov_pattern.findall(output)
            if cov_matches:
                cov = int(cov_matches[-1])
            else:
                cov = None

            self.update_fuzz_test_in_db(id, run_output=output, coverage=cov, exception=exception, crash=crash)

    def initial_fuzz_analysis(self, lib):
        fuzz_files = get_fuzz_tests_from_db(self.sqlitedb, lib)
        for file in fuzz_files:
            id, file_name, function_name, contents = file
            output = run_initial_atheris_fuzzer(contents)
            #print("+------------------------------------+")
            #print(output)

            if 'Done 2 runs' in output:
                self.update_fuzz_test_in_db(id, runs=True, run_output=output)
            elif 'Exception' in output:
                self.update_fuzz_test_in_db(id, runs=False, run_output=output, exception=True)
            else:
                self.update_fuzz_test_in_db(id, runs=False, run_output=output)

    def add_fuzz_files_to_prompt(self, file_data):
        fuzz_prompt_context = ''
        for function_name, contents in file_data:
            fuzz_prompt_context += f"example fuzzer for {function_name}:\n{contents}\n"
        return fuzz_prompt_context
    
    def install_package(self, package_name):
        subprocess.check_call(["python", "-m", "pip", "install", package_name])

    def is_package_installed(self, package_name):
        spec = importlib.util.find_spec(package_name)
        return spec is not None

    """def get_python_functions_and_code_from_library(self, library_name, function_list=None):
        funcs = {}

        if not self.is_package_installed(library_name):
            if not self.install_package(library_name):
                print("Unable to import and install library")
                return funcs

        try:
            library = importlib.import_module(library_name)
        except ImportError:
            print("Unable to import and install library")
            return funcs

        for _, name, is_pkg in pkgutil.walk_packages(library.__path__):
            if is_pkg:
                continue
            try:
                module = importlib.import_module(f"{library_name}.{name}")

                for func_name, obj in inspect.getmembers(module):
                    if inspect.isfunction(obj) and (function_list is None or func_name in function_list):
                        funcs.update({func_name: inspect.getsource(obj)})
            except Exception as e:
                print(f"Error loading module {name}: {e}")
        return funcs"""
    
    def generate_fuzz_tests(self, library_name, function_list=None):
        base_template = open(self.base_prompt_path, "r").read()
        fuzz_file_data = self.get_existing_fuzz_file_data(library_name)
        fuzzer_context = self.add_fuzz_files_to_prompt(fuzz_file_data)
        with self.db as db:
            functions = db.get_functions_from_db(self.sqlitedb, library_name, function_list)
                # Above was setup, below we create the full prompt, generate the fuzz test, and save it to the db
        for function in functions:
            complete_prompt = self.create_prompt(base_template, fuzzer_context, library_name, function.function_name, function.function_code)
            if not self.db.generated_file_exists(library_name, function.function_name):
                fuzz_test_code = self.generate_fuzz_code(complete_prompt)
                self.save_fuzz_test_to_db(library_name, function.function_name, fuzz_test_code)
                print("=" * 50)
                print(function.function_name)

    def get_radon_functions_from_db(self, lib_name, score=None):
        engine = get_engine(self.sqlitedb)
        session = Session(engine)

        query = session.query(LibraryFile.function_name).filter(
            LibraryFile.library_name == lib_name,
            LibraryFile.type == "radon"
        )

        if score is not None:
            if isinstance(score, str):
                score = [score]
            query = query.filter(LibraryFile.complexity_score.in_(score))

        function_names = [result[0] for result in query.all()]

        session.close()
        return function_names

if __name__ == "__main__":
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
        }
    }

    # Initialize LangFuzz object
    langfuzz = LangFuzz(sqlitedb, 'python', base_prompts_path)

    # This defines the score of radon complexity to pull from the database
    # A and B are the highest scores, E and F are the lowest scores
    radon_score = ['C', 'D', 'E', 'F']
    # radon_score is optional, if you don't pass it, it will pull all the functions
    priority_funcs = LangFuzz.get_radon_functions_from_db('urllib3', radon_score)
    print(priority_funcs)
    langfuzz.generate_fuzz_tests('urllib3', priority_funcs)