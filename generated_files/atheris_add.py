import os
os.environ["OPENAI_API_KEY"] = "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"

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

def add(a,b):
    return a + b

def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
    sys.exit()

if __name__ == "__main__":
    main()