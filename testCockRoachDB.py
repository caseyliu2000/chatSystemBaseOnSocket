
db_pass='e3_zqOYLGKJAelKYksT-bA'
DATABASE_URL = f"postgresql://casey123:{db_pass}@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"

import psycopg2

conn = psycopg2.connect(DATABASE_URL)

with conn.cursor() as cur:
    cur.execute("SELECT now()")
    res = cur.fetchall()
    conn.commit()
    print(res)