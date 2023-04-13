import subprocess
import os
import sys

from .langfuzzDB import GeneratedFile, Library, LibraryFile, create_tables, get_engine
from sqlalchemy.orm import Session


def setup_atheris_environment() -> None:
    os.environ["ATHERIS_FUZZ_TEST"] = "1"
    os.environ["ATHERIS_NO_FORK_SERVER"] = "1"

def run_initial_atheris_fuzzer(input_text: str) -> str:
    input_text = input_text.strip().strip("```")
    with open("fuzz_test.py", "w") as f:
        f.write(input_text)
    setup_atheris_environment()
    try:
        output = subprocess.check_output(
            [sys.executable, "fuzz_test.py", "-runs=2"], stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        output = e.output
    finally:
        os.remove("fuzz_test.py")
    # clean up created crash files, defined as crash-* regex
    subprocess.run(['rm', 'crash-*'])
    # Remove the first 7 lines of the output, which are the Atheris initialization logs
    output_lines = output.decode().splitlines()
    output = "\n".join(output_lines[7:])
    return output

import tiktoken

def num_tokens_from_string(string: str) -> int:
    """Returns the number of tokens in a text string."""
    encoding = tiktoken.encoding_for_model("gpt-4")
    num_tokens = len(encoding.encode(string))
    return num_tokens

# change to get_lib_fuzz_tests_from_db, add get_all_fuzz_tests_from_db, move to utils
def get_fuzz_tests_from_db(sqlitedb, library_name):
    engine = get_engine(sqlitedb)
    create_tables(engine)
    session = Session(engine)
    query = session.query(GeneratedFile.id, GeneratedFile.file_name, GeneratedFile.function_name, GeneratedFile.contents).filter(
        GeneratedFile.library_name == library_name,
        GeneratedFile.fuzz_test == True
        )
    fuzz_tests = query.all()
    session.close()
    return fuzz_tests