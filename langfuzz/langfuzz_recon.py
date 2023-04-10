import os
import git
import inspect
import importlib
import pkgutil
import sys
import subprocess

from .langfuzzDB import Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session

class LangFuzzRecon:
    def __init__(self, sqlitedb, repo_path):
        self.sqlitedb = sqlitedb
        self.repo_path = repo_path
        os.makedirs(repo_path) if not os.path.exists(repo_path) else None

        # Download the oss-fuzz repository
        self.download_oss_fuzz_repo()

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

    def get_fuzz_files(self, lib_dict):
        fuzz_files = {}
        for key in lib_dict:
            path = self.repo_path + '/oss-fuzz/projects/' + str(key)
            fuzz_files[str(key)] = []
        # if the path exists, find all fuzz files
            if os.path.exists(path):
                for root, dirs, files in os.walk(path):
                    for file in files:
                        if file.startswith("fuzz") and file.endswith(".py"):
                            fuzz_files[key].append(os.path.join(root, file))
            else:
                print(f"{key} Repo does not exist")
        return(fuzz_files)

    #save library data to database
    def save_libs(self, lib_dict, lang):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        for library_name, lib_data in lib_dict.items():
            github_url = lib_data['github']
            docs_url = lib_data['docs']
            language = lang

            existing_lib = session.query(Library).filter_by(library_name=library_name).first()
            if existing_lib is None:
                lib = Library(library_name=library_name, github_url=github_url, docs_url=docs_url, language=language)
                session.add(lib)
            else:
                print(f"Library {library_name} already exists, skipping.")

        session.commit()
        session.close()

    def save_fuzz_files(self, fuzz_files, lang):
        engine = get_engine(self.sqlitedb)
        create_tables(engine)
        session = Session(engine)

        for library_name, file_list in fuzz_files.items():
            for file_path in file_list:
                file_name = os.path.basename(file_path)
                with open(file_path, 'r') as f:
                    lines = f.readlines()
                first_source_line_index = next((index for index, line in enumerate(lines) if line.startswith("import")), 0)
                contents = "".join(lines[first_source_line_index:])

                existing_file = session.query(LibraryFile).filter_by(library_name=library_name, file_name=file_name).first()
                if existing_file is None:
                    lib_file = LibraryFile(library_name=library_name, file_name=file_name, contents=contents, generated=False, fuzz_test=True, type="fuzzer")
                    session.add(lib_file)
                else:
                    print(f"File {file_name} already exists for library {library_name}, skipping.")
        session.commit()
        session.close()

    def save_recon_data(self, libs, fuzz_files, lang):
        self.save_libs(libs, lang)
        self.save_fuzz_files(fuzz_files, lang)

    def get_functions_and_code_from_library(self, library_name):
        funcs = {}
        library = importlib.import_module(library_name)
    # Iterate through all the modules within the library
        for _, name, is_pkg in pkgutil.walk_packages(library.__path__):
            if is_pkg:
                continue
            try:
                module = importlib.import_module(f"{library_name}.{name}")

                for func_name, obj in inspect.getmembers(module):
                    if inspect.isfunction(obj):
                        funcs.update({func_name: inspect.getsource(obj)})
            except Exception as e:
                print(f"Error loading module {name}: {e}")
        return funcs

    def run_radon_analysis(self, library_name):
    # Define the paths for the library source and the output file
        src_path = os.path.join(self.repo_path, library_name, "src")
        radon_file_path = os.path.join("generated_files", f"{library_name}_functions.txt")
    
    # Make sure the output directory exists
        os.makedirs("generated_files", exist_ok=True)

    # Run the Radon analysis and save the output to a file
        with open(radon_file_path, "w") as radon_file:
            radon_output = subprocess.run(
                ["radon", "cc", src_path],
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

    def parse_radon_analysis(self, radon_file_path):
        function_list = []
        with open(radon_file_path, "r") as radon_file:
            for line in radon_file:  # Iterate through the lines of the file
                line = line.strip()  # Call strip() on the line, not the file object
                parts = line.split()
                function_name = parts[2]

                if not function_name.startswith('_'):
                    score = parts[-1]
                    function_list.append((function_name, score))
        return sorted(function_list, key=lambda x: x[1])

    def radon_complexity_filter(self, function_list):
        filtered_function_list = []
        for function_name, score in function_list:
            if score not in ('A', 'B'):
                filtered_function_list.append(function_name)
        return filtered_function_list

    def radon_metrics(self, library_name):
        file_path = self.run_radon_analysis(library_name)
        function_list = self.parse_radon_analysis(file_path)
        return self.radon_complexity_filter(function_list)



def main():
    repo_path = "../github_repos"
    sqlitedb = "langfuzz.db"
    http_libs = {
     'urllib3': {
    'github': 'https://github.com/urllib3/urllib3',
    'docs': 'https://urllib3.readthedocs.io/en/stable/'
    }}
    utils = {
    'oss-fuzz': {
	 'github': 'https://github.com/google/oss-fuzz'
	 }}
    libs = [http_libs, utils]

    langfuzz_recon = LangFuzzRecon(sqlitedb, repo_path)
    langfuzz_recon.download_github_repos(libs)
    fuzz_files = langfuzz_recon.get_fuzz_files(http_libs)
    langfuzz_recon.save_recon_data(http_libs, fuzz_files, 'python')

    for library_name, lib_data in http_libs.items():
        functions = langfuzz_recon.get_functions_and_code_from_library(library_name)
        #print(functions)

      #get functions with high cyclomatic complexity
    complex_radon_funcs = langfuzz_recon.radon_metrics('urllib3')
    

    priority_funcs = ['create_urllib3_context', 'ssl_wrap_socket','match_hostname', 'parse_url']


if __name__ == "__main__":
    main()