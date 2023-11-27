# Get-UserSession
Queries user sessions for the entire domain (Interactive/RDP etc), allowing you to query a user and see all his logged on sessions, whether Active or Disconnected.

Agentless, pure "living off the land" (No dependencies required, e.g. no ActiveDirectory Module needed or RSAT) for mapping user session in a 'Hacktive Directory' domain.

Run w/account that has Local Admin on domain endpoints. relays on port 445 to be open on the endPoints (quser.exe tool is used).

By default, tries to query all enabled computer accounts in the domain. Can also specify specific computer(s).

Comments & feedback welcome.


Note: 
### If you do Not have Admin rights, and/or you're looking to know both accounts connected via SMB shares as well as interactive, try "Get-UserSession2" script (https://github.com/YossiSassi/Get-UserSession2) 
