from langfuzz.tools.python_repl import PythonREPLFuzzTool
import openai
import time

def fix_code(code, output):
    # Use OpenAI GPT to generate a fixed version of the code
    # Modify the code to fix the problem
    # Return the updated code
    prompt=f"Fix the following code:\n{code}\nOutput: {output}",

    response = openai.ChatCompletion.create(
            model='gpt-3.5-turbo',
            messages=[
                {"role": "system", "content": prompt}],
            max_tokens=1550,
            temperature=0.6,
        )
    return response["choices"][0]["message"]["content"]


fuzz_tool = PythonREPLFuzzTool()
function_list = # TODO: Load function code strings here
for function_code in function_list:
    output = fuzz_tool.run_fuzz_test(function_code)
    verified_run = 'Done 2 runs'
    n = 0
    while n < 10:
        n += 1
        fixed_code = fix_code(function_code, output)
        print(fixed_code)
        new_output = fuzz_tool.run_fuzz_test(fixed_code)
        if verified_run in new_output:
            print('fixed')
        else:
            output = new_output
            time.sleep(1)
