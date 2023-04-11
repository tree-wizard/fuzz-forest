import os
import git
import subprocess
import sqlite3

from .langfuzzDB import Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session

class LangFuzzRecon:
    def __init__(self, sqlitedb, github_repo_path, target_libraries, language):
        self.sqlitedb = sqlitedb
        self.repo_path = github_repo_path
        self.language = language
        os.makedirs(github_repo_path) if not os.path.exists(github_repo_path) else None

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

        os.makedirs(os.path.join(self.repo_path, "generated_files"), exist_ok=True)

        with open(radon_file_path, "w") as radon_file:
            radon_output = subprocess.run(
                ["radon", "cc", "--exclude", "*test*", src_path],
                stdout=subprocess.PIPE,
                text=True,
                check=True
            )
            grep_output = subprocess.run(
                ["grep", "-E", r"^\s*F\s+"],
                input=radon_output.stdout,
                stdout=subprocess.PIPE,
                text=True
            )

            if grep_output.returncode == 0:
                radon_file.write(grep_output.stdout)
            elif grep_output.returncode == 1:
                print(f"No matching functions found for library {library_name}")
            else:
                grep_output.check_returncode()

        return radon_file_path

    def parse_save_radon_analysis(self, radon_file_path, library_name):
        with open(radon_file_path, "r") as radon_file:
            file_name = None
            for line in radon_file:
                line = line.strip()
                if line.endswith(".py"):
                    file_name = line
                else:
                    parts = line.split()
                    if parts[0] == 'F':
                        function_name = parts[2]
                        if not function_name.startswith('_'):
                            score = parts[-1]
                            self.save_radon_result(library_name, file_name, function_name, score)

    def save_radon_result(self, library_name, file_name, function_name, complexity_score):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        radon_result = LibraryFile(
            library_name=library_name,
            file_name=file_name,
            function_name=function_name,
            fuzz_test=False,
            language=self.language,
            complexity_score=complexity_score,
            type="radon"
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
