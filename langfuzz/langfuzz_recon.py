import os
import git
import subprocess
import sqlite3
import re
import json

from .langfuzzDB import Database, Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session

class LangFuzzRecon:
    def __init__(self, sqlitedb, repo_path, target_libraries, language):
        self.db = Database(sqlitedb)
        self.sqlitedb = sqlitedb
        self.repo_path = repo_path
        self.language = language
        os.makedirs(repo_path) if not os.path.exists(repo_path) else None

        # Create the SQLite database file if it doesn't exist
        if not os.path.exists(sqlitedb):
            with sqlite3.connect(sqlitedb) as conn:
                pass
        engine = get_engine(sqlitedb)
        create_tables(engine)

        self.save_library_info(target_libraries)
        # Download the oss-fuzz repository
        self.download_oss_fuzz_repo()
        # download the github repositories
        self.download_github_repos(target_libraries)
        self.get_fuzz_files(target_libraries)
        self.radon_analysis(target_libraries)
        self.get_code_all_functions(target_libraries)
        self.clean_functions_in_DB(target_libraries)

    def download_oss_fuzz_repo(self):
        repo_dir = os.path.join(self.repo_path, 'oss-fuzz')
        git_url = 'https://github.com/google/oss-fuzz'
        if not os.path.exists(repo_dir):
            print(f"Cloning oss-fuzz from {git_url}...")
            git.Repo.clone_from(git_url, repo_dir)

    def download_github_repos(self, libraries_info):
        for lib_name, lib_data in libraries_info.items():
            repo_dir = os.path.join(self.repo_path, lib_name)
            if not os.path.exists(repo_dir):
                if isinstance(lib_data, str):
                    git_url = lib_data
                elif isinstance(lib_data, dict) and "github" in lib_data:
                    git_url = lib_data["github"]
                else:
                    print(f"Invalid data for {lib_name}, skipping download.")
                    continue
                print(f"Cloning {lib_name} from {git_url}...")
                git.Repo.clone_from(git_url, repo_dir)

    def get_fuzz_files(self, libraries_info):
        for key in libraries_info:
            self.find_fuzz_in_oss_fuzz(key)
            self.find_fuzz_in_repo(key)

    def find_fuzz_in_oss_fuzz(self, library_name):
        path = os.path.join(self.repo_path, 'oss-fuzz', 'projects', library_name)
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.startswith("fuzz") and file.endswith(".py"):
                        file_path = os.path.join(root, file)
                        self.save_fuzz_file(library_name, file_path, "fuzzer")

    def find_fuzz_in_repo(self, library_name):
        path = os.path.join(self.repo_path, library_name)
        if os.path.exists(path):
            for root, dirs, files in os.walk(path):
                for file in files:
                    if 'fuzz' in file and file.endswith(".py"):
                        file_path = os.path.join(root, file)
                        self.save_fuzz_file(library_name, file_path, "fuzzer")
        else:
            print(f"{library_name} Repo does not exist")

    def get_code_all_functions(self, libraries_info):
        for library_name in libraries_info.keys():
            with self.db as db:
                functions = db.get_functions_from_db(library_name)
            
                for func in functions:
                    file_path = func.file_path
                    file_line_start = func.file_line_start
                    file_line_end = func.file_line_end

                    if file_path is not None:
                        function_code = self.get_function_code(file_path, file_line_start, file_line_end)

                        if function_code:
                            self.update_function_contents_in_db(library_name, func.file_name, func.function_name, function_code)

    def clean_functions_in_DB(self, libraries_info):
        for library_name in libraries_info.keys():
            with self.db as db:
                db.clean_functions_in_DB(library_name)
                
    def update_function_contents_in_db(self, library_name, file_name, function_name, function_code):
        engine = get_engine(self.sqlitedb)
        session = Session(engine)

        function = session.query(LibraryFile).filter_by(
            library_name=library_name,
            file_name=file_name,
            function_name=function_name
        ).first()

        if function:
            function.contents = function_code
            session.commit()
        else:
            print(f"Function {function_name} not found in {library_name}/{file_name}")

        session.close()

    def get_function_code(self, file_path, file_line_start, file_line_end):
      with open(file_path, 'r') as f:
          lines = f.readlines()
      function_lines = lines[file_line_start-1:file_line_end]
      function_code = ''.join(function_lines)
      return function_code

    def save_fuzz_file(self, library_name, file_path, file_type):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        file_name = os.path.basename(file_path)
        with open(file_path, 'r') as f:
            lines = f.readlines()
        first_source_line_index = next((index for index, line in enumerate(lines) if line.startswith("import")), 0)
        contents = "".join(lines[first_source_line_index:])

        existing_file = session.query(LibraryFile).filter_by(library_name=library_name, file_name=file_name).first()
        if existing_file is None:
            lib_file = LibraryFile(library_name=library_name, file_name=file_name, contents=contents, fuzz_test=True, language=self.language, type=file_type)
            session.add(lib_file)
        
        session.commit()
        session.close()

    def save_library_info(self, libraries_info):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        for library_name, lib_data in libraries_info.items():
            if isinstance(lib_data, str):
                github_url = lib_data
                docs_url = None
            elif isinstance(lib_data, dict):
                github_url = lib_data['github']
                docs_url = lib_data.get('docs', None)

            existing_lib = session.query(Library).filter_by(library_name=library_name).first()
            if existing_lib is None:
                lib = Library(library_name=library_name, github_url=github_url, docs_url=docs_url, language=self.language)
                session.add(lib)

        session.commit()
        session.close()

    def run_radon_tool(self, library_name):
       source_path = os.path.join(self.repo_path, library_name)
       os.makedirs(os.path.join(self.repo_path, "generated_files", "radon"), exist_ok=True)
       radon_file_name = f"{library_name}_functions.json"
       radon_file_path = os.path.join(self.repo_path, "generated_files", "radon", radon_file_name)

       radon_output = subprocess.run(
           ["radon", "cc", "--exclude", "*test*,*docs*", source_path, "-j"],
           stdout=subprocess.PIPE,
           text=True,
           check=True
       )

       # save radon output to file
       with open(radon_file_path, "w") as radon_file:
           radon_file.write(radon_output.stdout)

       if not radon_output.stdout:
           print(f"Unable to run radon for {library_name}")
        
       return radon_file_path

    def parse_save_radon_analysis(self, radon_file_path, library_name):
       with open(radon_file_path, 'r') as f:
        data = json.load(f)

        for file_path, functions in data.items():
            file_name = file_path.split('/')[-1]

            for function in functions:
                if function['type'] == 'function' and not function['name'].startswith('_'):
                #    print(f"file_name={file_name}")
                #    print(f"file_path={file_path}")
                #    print(f"function_name={function['name']}")
                #    print(f"file_line_start={function['lineno']}")
                #    print(f"file_line_end={function['endline']}")
                #    print(f"score={function['rank']}")
                    self.save_radon_result(library_name, file_name, file_path, function['name'], function['lineno'], function['endline'], function['rank'])

        # add line number file_path 
    def save_radon_result(self, library_name, file_name, file_path, function_name, file_line_start, file_line_end, score):
        with self.db as db:
            db.save_radon_result(library_name, file_name, self.language, file_path, function_name, file_line_start, file_line_end, score)

    def radon_analysis(self, libraries_info):
        for library_name in libraries_info.keys():
            file_path = self.run_radon_tool(library_name)
            self.parse_save_radon_analysis(file_path, library_name)

def main():
    current_directory = os.path.dirname(os.path.abspath(__file__))
    repo_path = os.path.join(current_directory, 'github_repos')
    sqlitedb = os.path.join(current_directory, 'langfuzz.db')
    http_libs = {
        'urllib3': {
            'github': 'https://github.com/urllib3/urllib3',
            'docs': 'https://urllib3.readthedocs.io/en/stable/'
        }
    }

    langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path, http_libs, 'python')

if __name__ == "__main__":
    main()
