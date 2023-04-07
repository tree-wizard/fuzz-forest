import sys
import os
import subprocess
from io import StringIO
from typing import Dict, Optional
import threading

from pydantic import BaseModel, Field
from llm_agents.tools.base import ToolInterface


class PythonREPL(BaseModel):
    """Simulates a standalone Python REPL."""

    globals: Optional[Dict] = Field(default_factory=dict, alias="_globals")
    locals: Optional[Dict] = Field(default_factory=dict, alias="_locals")
    lock: threading.Lock = Field(default_factory=threading.Lock)

    def run(self, command: str, timeout: Optional[float] = None) -> str:
        """Run command with own globals/locals and returns anything printed."""
        def _run():
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

        with self.lock:
            if timeout is not None:
                t = threading.Timer(timeout, sys.exit)
                t.start()

            output = _run()

            if timeout is not None:
                t.cancel()

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

    def use(self, input_text: str) -> str:
        input_text = input_text.strip().strip("```")
        with open("fuzz_test.py", "w") as f:
            f.write(input_text)

        setup_atheris_environment()

        try:
            output = subprocess.check_output(
                [sys.executable, "fuzz_test.py"], stderr=subprocess.STDOUT
            )
        except subprocess.CalledProcessError as e:
            output = e.output
        finally:
            os.remove("fuzz_test.py")
        return output.decode()


if __name__ == '__main__':
    repl_tool = PythonREPLTool()
    result = repl_tool.use('print(5 * 7)')
    assert result == "35\n"
    print(result)

    fuzz_tool = PythonREPLFuzzTool()
    example1 = """import atheris
import sys

def test(data):
if data == b'crash':
raise RuntimeError("You found the crash!")

atheris.Setup(sys.argv, test)
atheris.Fuzz()
"""
    result = fuzz_tool.use(example1)
    print(result)

