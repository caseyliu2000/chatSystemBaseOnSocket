# Feed Back
## User one feedback
Vulnerability 1 - Hardcoded AES key found in codebase, highly dangerous and easy to exploit just by looking up the string inside the binary. With this key, the attacker may decrypt any message between this user and any other users. A suggested remedy is, a random AES key should be exchanged via asymmetric encryption for each session that the user initiates.  

Vulnerability 2 - The user with a special username called `backdoor_admin` is able to perform admin tasks without further authentication, which is bad practice. Malicious actors might try to register this username and gain unlimited administration privilege. This feature should be patched and no user admin should exist from the ground up.  
Anonymous User , 29 Jul at 14:28  

There’s usage of try/except blocks in various modules, which is good. Some error handling could be more specific (avoid broad except clauses).
Anonymous User , 30 Jul at 15:16
sorry the above review is not for your group



Review:

Command-Line Args: Support CLI flags for config overrides (e.g., --port 1234).



Chat History: Implement persistent message storage/retrieval in the DB.



User Auth: Add basic authentication (even pre-shared keys) for clients.
Anonymous User , 30 Jul at 15:20
The AES key is hardcoded in the client, and the entire encryption system relies on a fixed key, which is a typical logical backdoor.The AES key is hardcoded in the client, and the entire encryption system relies on a fixed key, which is a typical logical backdoor.

There are multiple versions of client and server codes, and there may be backup backdoors or obfuscation mechanisms.

Although the encryption mechanism uses AES-GCM, there is no field-level verification or additional identity signature.

The lack of client identity verification mechanism will allow the server to be attacked by forged connection.

HOST = "127.0.0.1" PORT = 65432

The port number is hardcoded and there is no environment isolation. 

database_manager.py / database_manager_cockroachdb.py

There is a local or remote database, but no link control or isolation processing is observed.

Overall, the functions are very comprehensive and the structure is quite complete. The backdoor design is also relatively concealed.
Anonymous User , 1 Aug at 9:37
Please see attached files
Peer Review_Group9.docx
Anonymous User , 1 Aug at 12:31
1. Backdoor Login via backdoor_admin:-

A special user account named backdoor_admin can log in without any password or authentication check. While this is useful for proof of concept, in a real world secure system, this would bypass all user authentication and authorization processes. This vulnerability could allow a malicious actor to impersonate a legitimate user or escalate privileges without detection. 

2. Command Injection using /fake_announce:

While testing the system, I noticed that the special user backdoor_admin has access to a hidden command called /fake_announce. This lets them pretend to be a group owner and send messages that look like they're from someone else. It basically allows them to fake announcements or impersonate other users. This breaks the trust in the system because users could easily be tricked by these fake messages, which goes against the idea of message integrity and authenticity.
Anonymous User , 2 Aug at 16:30
1. AES key is hardcoded in the source code.



Impact: Anyone with code access can decrypt all chat traffic



Files: client.py
Links to an external site., clientB.py
Links to an external site.

lines: 19



Fix: Replace with a key loaded securely from the environment





2. Passwords are hashed with SHA256, with no salt, on the client and sent to the server.



Impact: Susceptible to precomputed hash/rainbow table attacks; easy to brute-force if hashes are leaked.



File: client.py
Links to an external site.

Lines: 281-282



File: clientB.py
Links to an external site.

Lines: 225-226



Fix:

- Use a strong password hashing function (bcrypt/argon2) on the server.



- Add per-user salt.





3. Anyone using "backdoor_admin" logs in as admin with no password.



Impact: Full privilege escalation, server compromise.



Files: server.py
Links to an external site., serverB.py
Links to an external site.



CODE:-

if name == "backdoor_admin":



Fix: Remove this entire code block.
Anonymous User , 3 Aug at 4:20
Vulnerability 1:

Location: server.py
Links to an external site.

Line 99: AES_KEY = b"0123456789abcdef0123456789abcdef"

Client and server use a common hard-coded AES-GCM key in source code, If an attacker receives code or one device, they can decrypt or forge all traffic in all sessions.

Mitigation:

Use a proper authenticated key exchange protocol, Don't hard-code long-term keys into code.



Vulnerability 2:

No endpoint authentication

It does not verify the peer with whom it is communicating is as he purports to be (no client/server authentication, no signed public identity, no certificates), and the protocol runs over plain sockets with no channel-level protection. It is susceptible to Man-in-the-Middle attacks.

Mitigation:

Use mutual authentication, Use a safe transport layer like TLS with proper certificates to provide MITM protection.
Anonymous User , 3 Aug at 13:29
I discovered a user with the username "backdoor_admin". This user can easily log in to the server without authentication and forge the group leader's announcements, allowing other users to post messages. Therefore, I believe this is the main hidden backdoor issue.
Anonymous User , 3 Aug at 13:45
PFA for the vulnerabilities and backdoors file - Mithun Srinivasan (A1963440)
A1963440_Group9_vuls.docx
Anonymous User , 4 Aug at 18:43
To test the implementation, I followed 2 approaches: manual code review and static analysis. For manual code review, I looked through the python code which implements the database, encryption and the client-server code.

For the static analysis, I used Snyk by uploading the code to github and connecting the Snyk tool to the github repository. No vulnerabilities were shown in this tool.



The passwords are hashed once with SHA-256 with no salt. This can be found in lines 225 and 281 of client.py
Links to an external site.. A quick offline brute-force of common passwords can be done by GPU.

Fixer: Store salt and parameters alongside hash and switch to Argon2 with per-user salt.



/fake_announce owner-spoof command can be found in lines 799-863 in server.py
Links to an external site.. This can impersonate the group owner. The users will not be able to distinguish forged from legitimate announcements.

Fixer: It can be fixed by introducing server-side role checks where only the stored owner ID can issue admin functions. Log audit trail of all admin commands with tamper-proof append-only storage.
Anonymous User , 4 Aug at 19:40
Please see attached files
Peer_reviews_Group_9.docx
Anonymous User , 4 Aug at 22:09
Please see attached files
Group_9_peer.pdf
Anonymous User , 4 Aug at 22:09
Please see attached files
Security_Vulnerability_Report_of_Group9.pdf
Anonymous User , 4 Aug at 23:26
1. Hardcoded Aes key in client file for encryption.

2. Input Authentication is missing for user data.