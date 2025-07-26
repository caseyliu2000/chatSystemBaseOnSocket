from dotenv import load_dotenv
import os

#默认使用defaultdb，如果需要使用其他db，请修改DATABASE_URL
DATABASE_URL = "postgresql://casey123:<password>@smiley-mule-7838.jxf.gcp-asia-southeast1.cockroachlabs.cloud:26257/defaultdb?sslmode=verify-full"
import psycopg2
# load_dotenv("wg.env")#載入環境变量
# DATABASE_URL = os.getenv("DATABASE_URL")

conn = psycopg2.connect(DATABASE_URL)

#測試連線
# with conn.cursor() as cur:
#     cur.execute("SELECT now()")
#     res = cur.fetchall()
#     conn.commit()
#     print(res)


#建立server_info_table
'''
server_id          BIGINT PRIMARY KEY,                      -- uint64 对应 BIGINT
    server_name        CHAR(64),                                -- 可选的名字
    server_pubip       BYTEA,                                   -- 公网 IP，bytes[16]
    server_port        SMALLINT,                                -- 端口，uint16
    server_privip      BYTEA,                                   -- 内网 IP，bytes[16]
    server_pubkey      BYTEA,                                   -- WireGuard 公钥，bytes[32]
    server_presharedkey BYTEA                                   -- WireGuard 预共享密钥，bytes[32]
'''
with conn.cursor() as cur:
    cur.execute("CREATE TABLE IF NOT EXISTS server_info_table (server_id BIGINT PRIMARY KEY, server_name CHAR(64), server_pubip BYTEA, server_port SMALLINT, server_privip BYTEA, server_pubkey BYTEA,server_presharedkey BYTEA)")
    conn.commit()
    print("Table created successfully")

#建立user_info_table
''' 
user_id            BIGINT PRIMARY KEY,                      -- uint64 对应 BIGINT
    user_id          BIGINT PRIMARY KEY,                  -- uint64
    username         CHAR(64) UNIQUE NOT NULL,            -- 全局唯一用户名
    display_name     VARCHAR(256),                        -- UTF8 显示名
    last_seen        TIMESTAMP,                           -- 最后上线时间（分钟精度）
    user_pubkey      BYTEA,                               -- 公钥，32字节
    invite_history   TIMESTAMP[],                         -- 邀请历史数组（分钟精度）
    latest_ip        BYTEA                                -- 最新 IP，16字节
'''
with conn.cursor() as cur:
    cur.execute("CREATE TABLE IF NOT EXISTS user_info_table (user_id BIGINT PRIMARY KEY, username CHAR(64) UNIQUE NOT NULL, display_name VARCHAR(256), last_seen TIMESTAMP, user_pubkey BYTEA, invite_history TIMESTAMP[], latest_ip BYTEA)")
    conn.commit()
    print("Table created successfully")

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