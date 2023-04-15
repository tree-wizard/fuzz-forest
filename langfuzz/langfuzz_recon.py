import os
import git
import subprocess
import sqlite3
import re

from .langfuzzDB import Library, LibraryFile, create_tables, get_engine, get_functions_from_db
from sqlalchemy.orm import Session

class LangFuzzRecon:
    def __init__(self, sqlitedb, repo_path, target_libraries, language):
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

    def download_oss_fuzz_repo(self):
        repo_dir = os.path.join(self.repo_path, 'oss-fuzz')
        git_url = 'https://github.com/google/oss-fuzz'
        if not os.path.exists(repo_dir):
            print(f"Cloning oss-fuzz from {git_url}...")
            git.Repo.clone_from(git_url, repo_dir)
        else:
            print(f"oss-fuzz already exists, skipping download.")

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
            else:
                print(f"{lib_name} already exists, skipping download.")

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
        else:
            print(f"{library_name} Repo does not exist in oss-fuzz")

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
            functions = get_functions_from_db(self.sqlitedb, library_name)

            for func in functions:
                file_name = func.file_name
                function_name = func.function_name
                function_code = self.get_function_code(library_name, file_name, function_name)

                if function_code:
                    self.update_function_contents_in_db(library_name, file_name, function_name, function_code)


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

    def find_function_code(self, file_path, function_name):
        with open(file_path, "r") as f:
            lines = f.readlines()

        function_code = ""
        in_function = False
        indent_level = 0

        for line in lines:
            stripped_line = line.strip()

            if not in_function and re.match(r'^\s*@', line):
                # Skip decorators
                continue

            if not in_function and re.match(rf'^\s*def\s+{function_name}\s*\(', stripped_line):
                in_function = True
                indent_level = len(line) - len(stripped_line)

            if in_function:
                function_code += line

                if re.match(rf'^\s{{0,{indent_level}}}\S', line) and not re.match(rf'^\s*def\s+{function_name}\s*\(', stripped_line):
                    # We reached the end of the function
                    break

        return function_code

    def get_function_code(self, library_name, file_name, function_name):
        repo_dir = os.path.join(self.repo_path, library_name)

        # Search for the file in the repo directory
        for root, _, files in os.walk(repo_dir):
            if file_name in files:
                file_path = os.path.join(root, file_name)
                break
        else:
            print(f"File {file_name} not found in {repo_dir}")
            return None
        function_code = self.find_function_code(file_path, function_name)
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
        else:
            print(f"File {file_name} already exists for library {library_name}, skipping.")
        
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
            else:
                print(f"Library {library_name} already exists, skipping.")

        session.commit()
        session.close()

    def run_radon_tool(self, library_name):
        src_path = os.path.join(self.repo_path, library_name)
        radon_file_path = os.path.join(self.repo_path, "generated_files", f"{library_name}_functions.txt")

        os.makedirs(os.path.join(self.repo_path, "generated_files", "radon"), exist_ok=True)

        with open(radon_file_path, "w") as radon_file:
            radon_output = subprocess.run(
                ["radon", "cc", "--exclude", "*test*", src_path],
                stdout=subprocess.PIPE,
                text=True,
                check=True
            )
            pattern = re.compile(r'^(.+?\.py)\n(?:.*\n)*?\s+F\s+\d+:\d+\s+(\w+)\s+[-A]+(\w)', re.MULTILINE)
            matches = pattern.findall(radon_output.stdout)

            for match in matches:
                file_name, function_name, score = match
                radon_file.write(f"{file_name} {function_name} {score}\n")
            if not matches:
                print(f"No matching functions found for library {library_name}")
        return radon_file_path

    def parse_save_radon_analysis(self, radon_file_path, library_name):
       with open(radon_file_path, "r") as radon_file:
           for line in radon_file:
               line = line.strip()
               parts = line.split()

               file_name = parts[0]
               function_name = parts[1]
               score = parts[2]

               if not function_name.startswith('_'):
                   self.save_radon_result(library_name, file_name, function_name, score)


    def save_radon_result(self, library_name, file_name, function_name, complexity_score):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        existing_entry = session.query(LibraryFile).filter(
            LibraryFile.library_name == library_name,
            LibraryFile.file_name == file_name,
            LibraryFile.function_name == function_name
        ).first()
    
        if not existing_entry:
            radon_result = LibraryFile(
                library_name=library_name,
                file_name=file_name,
                function_name=function_name,
                fuzz_test=False,
                language=self.language,
                complexity_score=complexity_score,
                type="source"
            )
            session.add(radon_result)
            session.commit()
        
        session.close()

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
