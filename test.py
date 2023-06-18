import atheris
import sys
import urllib3

def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    session = fdp.PickValueInList([None, "session"])

    try:
        if isinstance(session, str):
            urllib3.util.parse_url(session)
    except (TypeError, ValueError):
        pass

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()

