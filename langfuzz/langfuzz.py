import os
import openai
import inspect
import importlib
import pkgutil

from sqlalchemy.orm import Session

from .langfuzz_recon import LangFuzzRecon
from .langfuzzDB import Library, LibraryFile, create_tables, get_engine

class LangFuzz:
    def __init__(self, sqlitedb, language, base_prompt_path):
        self.sqlitedb = sqlitedb
        self.language = language
        self.base_prompt_path = base_prompt_path #replace with find_base_prompt_path()
        self.test = "test"

    def find_base_prompt_path(self):
        if self.language == "python":
            return os.path.join('prompts', 'base-atheris-prompt.py')
        else:
            raise Exception(f"Language {self.language} not supported.")

    def generate_test(self, prompt):
        response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": prompt}],
            max_tokens=1000,
            temperature=0.6,
        )
        return response["choices"][0]["message"]["content"]

    def create_prompt(self, prompt_template, target_function):
        prompt = prompt_template + f"{target_function}\n"
        return prompt

    def create_fuzz_test(self, prompt_template, target_function):
        prompt = self.create_prompt(prompt_template, target_function)
        fuzz_test = self.generate_test(prompt)
        return fuzz_test

    def add_fuzz_files_to_prompt(self, file_data):
        fuzz_prompt_context = ''
        for function_name, contents in file_data:
            fuzz_prompt_context += f"example fuzzer for {function_name}:\n{contents}\n"
        return fuzz_prompt_context
    
    def get_existing_fuzz_file_data(self, library_name):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        fuzz_files = session.query(LibraryFile).filter(LibraryFile.library_name == library_name, LibraryFile.fuzz_test == True).all()

        file_data = []
        for file in fuzz_files:
            file_data.append((file.function_name, file.contents))
        session.close()

        return file_data
    
    def get_python_functions_and_code_from_library(self, library_name, function_list=None):
        funcs = {}
        library = importlib.import_module(library_name)

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
        return funcs
    
    def generate_fuzz_tests(self, library_name, function_list=None):
        fuzz_file_data = self.get_existing_fuzz_file_data(library_name)
        fuzz_prompt_context = self.add_fuzz_files_to_prompt(fuzz_file_data)

        base_template = open(self.base_prompt_path, "r").read()
        prompt_template = base_template + fuzz_prompt_context + "write an atheris fuzzer for the following function:\n"

        if self.language == "python":
            function_info = self.get_python_functions_and_code_from_library(library_name, function_list)
        else:
            raise Exception(f"Language {self.language} not supported.")

        for func, contents in function_info.items():
            fuzz_test = self.create_fuzz_test(prompt_template, contents)
            print(fuzz_test)


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