import openai
import os

from pydantic import BaseModel, Field, validator
from typing import List, Optional

class ChatLLM(BaseModel):
    model: str = 'gpt-3.5-turbo'
    temperature: float = Field(default=0.0, ge=0, le=1)
    openai.api_key = os.environ["OPEN_API_KEY"]


    def generate(self, prompt: str, stop: List[str] = None) -> str:
        if not self.openai.api_key:
            raise ValueError("API key is missing or not set")

        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=self.temperature,
                stop=stop
            )
            return response.choices[0].message.content
        except openai.api_errors.OpenAIError as e:
            return f"An error occurred while generating a response: {str(e)}"

if __name__ == '__main__':
    llm = ChatLLM()
    result = llm.generate(prompt='Who is the president of the USA?')
    print(result)
