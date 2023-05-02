import sqlite3

# Define the path to your database file
db_path = "langfuzz-libs2.db"

# Connect to the SQLite database
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Delete rows with 'except Exception:' in the contents column
delete_query = """
DELETE FROM generated_files
WHERE contents LIKE '%except Exception as e%';
"""

cursor.execute(delete_query)
conn.commit()

# Close the database connection
cursor.close()
conn.close()

print("Deleted functions containing 'except Exception:' from the database.")
