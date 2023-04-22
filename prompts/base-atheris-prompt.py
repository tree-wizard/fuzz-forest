# Python fuzz tests with atheris library
# https://github.com/google/atheris
# Generic atheris fuzz test example:
import atheris
import sys
import struct
import example_library
def TestOneInput(data):
#The entry point for our fuzzer.
#  This is a callback that will be repeatedly invoked with different arguments
#  after Fuzz() is called.
#  We translate the arbitrary byte string into a format our function being fuzzed
#  can understand, then call it.
#  Args:   data: Bytestring coming from the fuzzing engine.
  if len(data) != 4:
    return  # Input must be 4 byte integer.
  number, = struct.unpack('<I', data)
  example_library.CodeBeingFuzzed(number)

 def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    atheris.instrument_all() # This is needed for coverage to work.
    main()

# When fuzzing Python, Atheris will report a failure if the Python code under test throws an uncaught exception.
# Atheris FuzzedDataProvider API Reference
# The FuzzedDataProvider is a class that provides a number of functions to consume bytes from the input and convert them into other forms.
# To construct the FuzzedDataProvider, use the following code:
fdp = atheris.FuzzedDataProvider(data)
# The FuzzedDataProvider provides the following functions, arguments are required unless otherwise specified:
# default arguments for int should be sys.maxsize like ConsumeInt(sys.maxsize)
# ConsumeBytes(count: int): Consume count bytes.
# ConsumeUnicode(count: int): Consume unicode characters. Might contain surrogate pair characters, which according to the specification are invalid in this situation. However, many core software tools (e.g. Windows file paths) support them, so other software often needs to too.
# ConsumeUnicodeNoSurrogates(count: int): Consume unicode characters, but never generate surrogate pair characters.
# ConsumeString(count: int): Alias for ConsumeBytes in Python 2, or ConsumeUnicode in Python 3.
# ConsumeInt(int: bytes): Consume a signed integer of the specified size (when written in two's complement notation).
# ConsumeUInt(int: bytes): Consume an unsigned integer of the specified size.
# ConsumeIntInRange(min: int, max: int): Consume an integer in the range [min, max].
# ConsumeIntList(count: int, bytes: int): Consume a list of count integers of size bytes.
# ConsumeIntListInRange(count: int, min: int, max: int): Consume a list of count integers in the range [min, max].
# ConsumeFloat(): Consume an arbitrary floating#point value. Might produce weird values like NaN and Inf.
# ConsumeRegularFloat(): Consume an arbitrary numeric floating#point value; never produces a special type like NaN or Inf.
# ConsumeProbability(): Consume a floating#point value in the range [0, 1].
# ConsumeFloatInRange(min: float, max: float): Consume a floating#point value in the range [min, max].
# ConsumeFloatList(count: int): Consume a list of count arbitrary floating#point values. Might produce weird values like NaN and Inf.
# ConsumeRegularFloatList(count: int): Consume a list of count arbitrary numeric floating#point values; never produces special types like NaN or Inf.
# ConsumeProbabilityList(count: int): Consume a list of count floats in the range [0, 1].
# ConsumeFloatListInRange(count: int, min: float, max: float): Consume a list of count floats in the range [min, max].
# PickValueInList(l: list): Given a list, pick a random value.
# ConsumeBool(): Consume either True or False.
# An example of fuzzing with a custom mutator in Python:
import atheris
import sys
import zlib

def CustomMutator(data, max_size, seed):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    decompressed = b'Hi'
  else:
    decompressed = atheris.Mutate(decompressed, len(decompressed))
  return zlib.compress(decompressed)

def TestOneInput(data):
  try:
    decompressed = zlib.decompress(data)
  except zlib.error:
    return
  if len(decompressed) < 2:
    return
  try:
    if decompressed.decode() == 'FU':
      raise RuntimeError('Boom')
  except UnicodeDecodeError:
    pass

def main():
  if len(sys.argv) > 1 and sys.argv[1] == '--no_mutator':
    atheris.Setup(sys.argv, TestOneInput)
  else:
    atheris.Setup(sys.argv, TestOneInput, custom_mutator=CustomMutator)
  atheris.Fuzz()
if __name__ == "__main__":
    atheris.instrument_all()
    main()

Make sure all fuzz test instrumented with the following code:

 def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    atheris.instrument_all()
    main()
