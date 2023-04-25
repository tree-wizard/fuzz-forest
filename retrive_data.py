import argparse
import sqlite3

# Create the argument parser
parser = argparse.ArgumentParser(description='Retrieve function names and contents from a SQLite database')
parser.add_argument('database', help='Path to the SQLite database')
parser.add_argument('--table', default='library_files', help='Name of the table to retrieve data from')
#parser.add_argument('--library', default='*', help='Name of the library to retrieve data from')
args = parser.parse_args()

# Establish connection to the database
conn = sqlite3.connect(args.database)

# Create a cursor object
cursor = conn.cursor()

# Execute the query
#query = f"SELECT function_name, run_output FROM {args.table};"
query = f"SELECT function_name, run_output FROM {args.table} WHERE LOWER(library_name) = 'cryptography';"

cursor.execute(query)

# Fetch all the results
results = cursor.fetchall()

# Print the results to the terminal
for row in results:
    print(row[0], "\n", row[1])
    print("=========================================")

print(len(results), "rows retrieved from the database")
# Close the cursor and the connection
cursor.close()
conn.close()
