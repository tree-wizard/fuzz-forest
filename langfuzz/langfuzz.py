import os
import openai
import inspect
import urllib3
from sqlalchemy.orm import Session

from langchain.prompts import PromptTemplate
from langchain.llms import OpenAI
from langchain.chains import LLMChain, SimpleSequentialChain

from .langfuzz_recon import LangFuzzRecon
from .langfuzzDB import Library, LibraryFile, create_tables, get_engine


class LangFuzz:
    def __init__(self, libraries, sqlitedb):
        self.libraries = libraries
        self.sqlitedb = sqlitedb

    def create_prompt(self, prompt_template, target_function):
        prompt = prompt_template + f"{target_function}\n"
        return prompt

    def generate_test(self, prompt):
        response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": prompt}],
            max_tokens=1000,
            temperature=0,
        )
        return response["choices"][0]["message"]["content"]

    def get_fuzz_files_contents(self, library_name):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        fuzz_files = session.query(LibraryFile).filter(LibraryFile.library_name == library_name, LibraryFile.fuzz_test == True).all()

        file_data = []
        for file in fuzz_files:
            file_data.append((file.file_name, file.contents))

        session.close()

        return file_data

    def add_fuzz_files_to_prompt(self, file_data):
        fuzz_prompt_context = ''
        for file_name, contents in file_data:
            fuzz_prompt_context += f"example fuzzer for {file_name}:\n{contents}\n"
        return fuzz_prompt_context

    def get_functions_from_module(self, module):
        funcs = {}
        for name, obj in inspect.getmembers(module):
            if inspect.isfunction(obj):
                funcs.update({name: (inspect.getsource(obj))})
        return funcs

    def create_fuzz_test(self, prompt_template, target_function):
        prompt = self.create_prompt(prompt_template, target_function)
        fuzz_test = self.generate_test(prompt)
        return fuzz_test

    def get_priority_funcs(all_funcs, priority_radon_funcs):
        funcs = {}
        for func, contents in all_funcs.items():
            if func in priority_radon_funcs:
                funcs.update({func: contents})
        return funcs

    def generate_fuzz_tests(self, library_name, base_template_path):
        base_template = open(base_template_path, "r").read()
        file_data = self.get_fuzz_files_contents(library_name)
        fuzz_prompt_context = self.add_fuzz_files_to_prompt(file_data)

        prompt_template = base_template + fuzz_prompt_context + "write an atheris fuzzer for the following function:\n"

        all_funcs = self.get_functions_from_module(library_name)
        print(all_funcs)
        priority_radon_funcs = langfuzz_recon.radon_metrics(library_name)

        funcs = self.get_priority_funcs(all_funcs, priority_radon_funcs)

        for func, contents in funcs.items():
            fuzz_test = self.create_fuzz_test(prompt_template, contents)
            print("=" * 50)
            print(fuzz_test)

#test
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
    langfuzz = LangFuzz(http_libs, 'langfuzz.db')

    # Initialize LangFuzzRecon object
    langfuzz_recon = LangFuzzRecon('github_repos', 'langfuzz.db')
    # Run recon
    #langfuzz_recon.run_recon()

    # Generate fuzz tests for urllib3
    lib = 'urllib3'
    prompt_path = "../prompts/base-atheris-prompt.py"
    langfuzz.generate_fuzz_tests(lib, prompt_path)

