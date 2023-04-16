import sys
import os
import subprocess
from io import StringIO
from typing import Dict, Optional

from pydantic import BaseModel, Field
from tools.base import ToolInterface


class PythonREPL(BaseModel):
    """Simulates a standalone Python REPL."""

    globals: Optional[Dict] = Field(default_factory=dict, alias="_globals")
    locals: Optional[Dict] = Field(default_factory=dict, alias="_locals")

    def run(self, command: str) -> str:
        """Run command with own globals/locals and returns anything printed."""
        old_stdout = sys.stdout
        sys.stdout = mystdout = StringIO()
        try:
            exec(command, self.globals, self.locals)
            sys.stdout = old_stdout
            output = mystdout.getvalue()
        except Exception as e:
            sys.stdout = old_stdout
            output = str(e)
        return output


def _get_default_python_repl() -> PythonREPL:
    return PythonREPL(_globals=globals(), _locals=None)


class PythonREPLTool(ToolInterface):
    """A tool for running python code in a REPL."""

    name: str = "Python REPL"
    description: str = (
        "A Python shell. Use this to execute python commands. "
        "Input should be a valid python command. "
        "If you want to see the output of a value, you should print it out "
        "with `print(...)`."
    )
    python_repl: PythonREPL = Field(default_factory=_get_default_python_repl)

    def use(self, input_text: str) -> str:
        input_text = input_text.strip().strip("```")
        return self.python_repl.run(input_text)


def setup_atheris_environment() -> None:
    os.environ["ATHERIS_FUZZ_TEST"] = "1"
    os.environ["ATHERIS_NO_FORK_SERVER"] = "1"


class PythonREPLFuzzTool(PythonREPLTool):
    """A tool for running Atheris fuzz tests in a REPL."""

    name: str = "Python REPL Fuzz"
    description: str = (
        "A Python shell for running Atheris fuzz tests. "
        "Input should be a valid python script containing Atheris fuzz test code."
    )

    def run_fuzz_test(self, input_text: str) -> str:
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
        # Remove the first 7 lines of the output, which are the Atheris initialization logs
        output_lines = output.decode().splitlines()
        output = "\n".join(output_lines[7:])
        return output


if __name__ == '__main__':
    repl_tool = PythonREPLTool()
    result = repl_tool.use('print(5 * 7)')
    assert result == "35\n"
    print(result)
    code = """import atheris
import sys

def test(data):
    if data == b'crash':
        raise RuntimeError("You found the crash!")

atheris.Setup(sys.argv, test)
atheris.Fuzz()
"""
    code1 = """
for fizzbuzz in range(51):
  if fizzbuzz % 3 == 0 and fizzbuzz % 5 == 0:
    print("fizzbuzz")
    continue
  elif fizzbuz % 3 == 0:
    print("fizz")
    continue
  elif fizzbuzz % 5 == 0:
    print("buzz")
    continue
print(fizzbuzz)
"""

    code2 = """
import atheris
import sys

@atheris.instrument_func
def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    a = fdp.ConsumeInt()
    b = fdp.ConsumeInt()
    try:
        add(a, b)
    except:
        pass

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
"""
    code3 = """
import sys
import atheris
import numpy as np

def TestOneInput(fuzz_data):
  fdp = atheris.FuzzedDataProvider(fuzz_data)
  x1 = np.array(fdp.ConsumeIntList(10, 4))
  x2 = np.array(fdp.ConsumeIntList(10, 4))
  np.matmul(x1, x2)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
  """
    code4 = """
import sys
import atheris
import numpy as np

def TestOneInput(fuzz_data):
  fdp = atheris.FuzzedDataProvider(fuzz_data)
  x1 = np.array(fdp.ConsumeIntList(10, 4))
  x2 = np.array(fdp.ConsumeIntList(10, 4))
  np.array_repr(x1, x2)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
    """
    code5 = """
import sys
import atheris
import numpy as np

def TestOneInput(fuzz_data):
  fdp = atheris.FuzzedDataProvider(fuzz_data)
  x1 = np.array(fdp.ConsumeIntList(10, 4))
  x2 = np.array(fdp.ConsumeIntList(10, 4))
  np.array_repr(x1, x2)

def main():
  atheris.instrument_all()
  atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
  atheris.Fuzz()

if __name__ == "__main__":
  main()
"""

    fuzz_tool = PythonREPLFuzzTool()
    result = fuzz_tool.run_fuzz_test(code)
    result1 = fuzz_tool.run_fuzz_test(code1)
    result2 = fuzz_tool.run_fuzz_test(code2)
    result3 = fuzz_tool.run_fuzz_test(code3)
    result4 = fuzz_tool.run_fuzz_test(code4)
    result5 = fuzz_tool.run_fuzz_test(code5)
    print("RESULT")
    print(result)
    print("RESULT1")
    print(result1)
    print("RESULT2")
    print(result2)
    print("RESULT3")
    print(result3)
    print("RESUL4")
    print(result4)
    print("RESULT5")
    print(result5)