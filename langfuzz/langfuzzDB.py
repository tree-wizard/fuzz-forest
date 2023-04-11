from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import declarative_base

Base = declarative_base()

class Library(Base):
    __tablename__ = "libraries"

    id = Column(Integer, primary_key=True)
    library_name = Column(String, unique=True)
    github_url = Column(String)
    docs_url = Column(String)
    language = Column(String)

class LibraryFile(Base):
    __tablename__ = "library_files"

    id = Column(Integer, primary_key=True)
    library_name = Column(String)
    file_name = Column(String)
    function_name = Column(String)
    contents = Column(Text)
    fuzz_test = Column(Boolean)
    language = Column(String)
    complexity_score = Column(String)
    type = Column(String) #fuzzer, test, radon, etc.

class GeneratedFile(Base):
    __tablename__ = "generated_files"

    id = Column(Integer, primary_key=True)
    library_name = Column(String)
    file_name = Column(String)
    contents = Column(Text)
    runs = Column(Boolean)
    fuzz_test = Column(Boolean)
    type = Column(String)
    coverage = Column(Text)
    cycles = Column(Integer)
    tokens = Column(Integer)

def create_tables(engine):
    Base.metadata.create_all(engine)

def get_engine(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    return engine
