from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session

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
    type = Column(String) #fuzzer, test, source, etc.

class GeneratedFile(Base):
    __tablename__ = "generated_files"

    id = Column(Integer, primary_key=True)
    library_name = Column(String)
    file_name = Column(String)
    function_name = Column(String)
    contents = Column(Text)
    runs = Column(Boolean)
    fuzz_test = Column(Boolean)
    type = Column(String)
    coverage = Column(Integer)
    cycles = Column(Integer)
    run_output = Column(Text)
    tokens = Column(Integer)
    crash = Column(Boolean)
    exception= Column(Boolean)

def create_tables(engine):
    Base.metadata.create_all(engine)

def get_engine(db_path):
    engine = create_engine(f"sqlite:///{db_path}")
    return engine

class Database:
    def __init__(self, db_path):
        self.engine = get_engine(db_path)
        create_tables(self.engine)
        self.session = Session(self.engine)

    def close(self):
        self.session.close()

    def get_functions_from_db(self, library_name, function_list=None):
        if function_list is not None:
            functions = self.session.query(LibraryFile).filter_by(library_name=library_name).filter(LibraryFile.function_name.in_(function_list)).all()
        else:
            functions = self.session.query(LibraryFile).filter_by(library_name=library_name).all()
        return functions

    def save_fuzz_test_to_db(self, library_name, function_name, file_name, fuzz_test_code, tokens):
        existing_file = self.session.query(GeneratedFile).filter(
            GeneratedFile.library_name == library_name,
            GeneratedFile.file_name == file_name
        ).first()

        if existing_file is None:
            generated_file = GeneratedFile(
                library_name=library_name,
                file_name=file_name,
                function_name=function_name,
                contents=fuzz_test_code,
                runs=False,
                fuzz_test=True,
                type='fuzz',
                coverage=None,
                cycles=None,
                tokens=tokens,
                exception=False
            )

            self.session.add(generated_file)
            self.session.commit()

    def update_fuzz_test_in_db(self, id, runs=None, run_output=None, coverage=None, exception=None, crash=None):
        fuzz_test = self.session.query(GeneratedFile).filter_by(id=id).first()
        if runs is not None:
            fuzz_test.runs = runs
        if run_output is not None:
            fuzz_test.run_output = run_output
        if coverage is not None:
            fuzz_test.coverage = coverage
        if exception is not None:
            fuzz_test.exception = exception
        if crash is not None:
            fuzz_test.crash = crash
        self.session.commit()

    def get_existing_fuzz_file_data(self, library_name):
        fuzz_files = self.session.query(LibraryFile.file_name, LibraryFile.function_name, LibraryFile.contents).filter_by(library_name=library_name, fuzz_test=True).all()
        return fuzz_files

    def get_functions_that_contain_string(self, library_name, search_string):
        results = self.session.query(LibraryFile.function_name).filter(LibraryFile.library_name == library_name).filter(LibraryFile.contents.contains(search_string)).all()
        return results
    
    def generated_file_exists(self, library_name, function_name):
        with Session(self.engine) as session:
            existing_file = session.query(GeneratedFile).filter(
                GeneratedFile.library_name == library_name,
                GeneratedFile.function_name == function_name
            ).first()
            return existing_file is not None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()