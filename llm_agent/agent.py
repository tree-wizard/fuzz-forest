import datetime
import re

from pydantic import BaseModel
from typing import List, Dict, Tuple

from llm_agent.llm import ChatLLM
from llm_agent.tools.base import ToolInterface
from llm_agent.tools.python_repl import PythonREPLTool 
from llm_agent.tools.search import SerpAPITool

FINAL_ANSWER_TOKEN = "Final Answer:"
OBSERVATION_TOKEN = "Observation:"
THOUGHT_TOKEN = "Thought:"
PROMPT_TEMPLATE = """Today is {today} and you can use tools to get new information. Review and fix the provided python code. Ignore coverage metrics. Your task is to run the code, If the code runs return Yes, else fix and return the code.You can using the following tools: 

{tool_description}

Use the following format:

Question: the input question you must answer
Thought: comment on what you want to do next
Action: the action to take, exactly one element of [{tool_names}]
Action Input: the input to the action
Observation: the result of the action
... (this Thought/Action/Action Input/Observation repeats N times, use it until you are sure of the answer)
Thought: I now have working code or know the final answer
Final Answer: your final answer to the original input question. Should be the last working and properly formatted python code with no extra text or 'Yes' if the code to runs correctly.

Begin!

Question: {question}
Thought: {previous_responses}
"""

class Agent(BaseModel):
    llm: ChatLLM
    tools: List[ToolInterface]
    prompt_template: str = PROMPT_TEMPLATE
    max_loops: int = 5
    stop_pattern: List[str] = [f'\n{OBSERVATION_TOKEN}', f'\n\t{OBSERVATION_TOKEN}']

    @property
    def tool_description(self) -> str:
        return "\n".join([f"{tool.name}: {tool.description}" for tool in self.tools])

    @property
    def tool_names(self) -> str:
        return ",".join([tool.name for tool in self.tools])

    @property
    def tool_by_names(self) -> Dict[str, ToolInterface]:
        return {tool.name: tool for tool in self.tools}

    def run(self, question: str):
        previous_responses = []
        num_loops = 0
        prompt = self.prompt_template.format(
                today = datetime.date.today(),
                tool_description=self.tool_description,
                tool_names=self.tool_names,
                question=question,
                previous_responses='{previous_responses}'
        )

        while num_loops < self.max_loops:
            num_loops += 1
            curr_prompt = prompt.format(previous_responses='\n'.join(previous_responses))
            generated, tool, tool_input = self.decide_next_action(curr_prompt)
            if tool == 'Final Answer':
                return tool_input
            if tool not in self.tool_by_names:
                raise ValueError(f"Unknown tool: {tool}")
            tool_result = self.tool_by_names[tool].use(tool_input)
            generated += f"\n{OBSERVATION_TOKEN} {tool_result}\n{THOUGHT_TOKEN}"
            previous_responses.append(generated)

    def decide_next_action(self, prompt: str) -> str:
        generated = self.llm.generate(prompt, stop=self.stop_pattern)
        tool, tool_input = self._parse(generated)
        return generated, tool, tool_input

    def _parse(self, generated: str) -> Tuple[str, str]:
        if FINAL_ANSWER_TOKEN in generated:
            return "Final Answer", generated.split(FINAL_ANSWER_TOKEN)[-1].strip()
        regex = r"Action: [\[]?(.*?)[\]]?[\n]*Action Input:[\s]*(.*)"
        match = re.search(regex, generated, re.DOTALL)
        if not match:
            raise ValueError(f"Output of LLM is not parsable for next tool use: {generated}")
        tool = match.group(1).strip()
        tool_input = match.group(2)
        return tool, tool_input.strip(" ").strip('"')

if __name__ == 'main':
  python = """for fizzbuzz in range(51):
if fizzbuzz % 3 == 0 and fizzbuzz % 5 == 0:
print("fizzbuzz")
continue
elif fizzbuz % 3 == 0:
print("fizz")
continue
elif fizbuzz % 5 == 0:
print("buzz")
continue
print(fizzbuzz)
"""
  agent = Agent(llm=ChatLLM(), tools=[PythonREPLTool(), SerpAPITool()])
  result = agent.run(python)
  print(result)
