# Python fuzz tests with atheris library
# https://github.com/google/atheris
"""
# Generic Atheris fuzz Example
# !/usr/bin/python3
import atheris
with atheris.instrument_imports():
  import some_library
  import sys
def TestOneInput(data):
  some_library.parse(data)
atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
# When fuzzing Python, Atheris will report a failure if the Python code under test throws an uncaught exception.
"""
# Atheris FuzzedDataProvider API Reference
# A bytes object may not convenient input to your code being fuzzed. FuzzedDataProvider allows conversion of bytes into other input forms.
# To construct the FuzzedDataProvider, use the following code:
# fdp = atheris.FuzzedDataProvider(input_bytes)
#The FuzzedDataProvider provides the following functions:
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