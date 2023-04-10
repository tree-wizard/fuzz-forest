from setuptools import setup, find_packages

setup(
    name='llm_agent',
    version='0.1.0',
    description='A package for building agents which use the OpenAI API to figure out actions to take and can use tools.',
    author='X',
    author_email='x@infiniteforest.org',
    url='https://github.com/xxyyx/llm_agent',
    packages=find_packages(),
    install_requires=[
        'google-search-results>=2.4.2',
        'openai>=0.27.0',
        'pydantic>=1.10.5',
        'requests>=2.28.2'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License'
    ],
)
