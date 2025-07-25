from dotenv import load_dotenv
import os

# DATABASE_URL = "postgresql://casey123:e3_zqOYLGKJAelKYksT-bA@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"
import psycopg2
# load_dotenv("wg.env")#載入環境变量
# DATABASE_URL = os.getenv("DATABASE_URL")

# conn = psycopg2.connect(DATABASE_URL)

#測試連線
# with conn.cursor() as cur:
#     cur.execute("SELECT now()")
#     res = cur.fetchall()
#     conn.commit()
#     print(res)


#建立tables
# with conn.cursor() as cur:
#     cur.execute("CREATE TABLE IF NOT EXISTS USERS (id INT, name STRING NOT NULL, age INT NOT NULL)")
#     conn.commit()
#     print("Table created successfully")

#插入資料
# with conn.cursor() as cur:
#     cur.execute("INSERT INTO USERS (id, name, age) VALUES (2, 'Casey', 24)")
#     conn.commit()
#     print("Data inserted successfully")

# #查詢資料
# with conn.cursor() as cur:
#     cur.execute("SELECT * FROM USERS")
#     res = cur.fetchall()
#     conn.commit()
#     print(res)

#测试remote DB
#DATABASE_URL = "postgresql://casey123:e3_zqOYLGKJAelKYksT-bA@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257
# /defaultdb?sslmode=verify-full"
#postgresql://<user>@<host>:<port>/<dbname>?sslmode=verify-full&sslrootcert=<path>&sslcert=<path>&sslkey=<path>

''' 基本配置 remoteDB. 
conn=psycopg2.connect(
    dbname="group5",
    user="group9",
    host="68.168.213.252",#own server ip
    port=26257,
    sslmode="verify-full",
    sslrootcert="certs/ca.crt",
    sslcert="certs/client.group9.crt",
    sslkey="certs/client.group9.key"
)
'''
CRDB_URL="postgresql://group9@68.168.213.252:26257/group5?sslmode=verify-full&sslrootcert=certs/ca.crt&sslcert=certs/client.group9.crt&sslkey=certs/client.group9.key"
conn = psycopg2.connect(CRDB_URL)

with conn.cursor() as cur:
    cur.execute("SHOW TABLES;")
    res = cur.fetchall()
    conn.commit()
    print(res)