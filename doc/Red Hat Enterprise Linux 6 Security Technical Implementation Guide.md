# Red Hat Enterprise Linux 6 Security Technical Implementation Guide

__Version:__ 1

__Release:__ 15

__Benchmark Date:__ 28 Apr 2017

The Red Hat Enterprise Linux 6 Security Technical Implementation Guide (STIG) is published as a tool to improve the security of Department of Defense (DoD) information systems.  Comments or proposed revisions to this document should be sent via e-mail to the following address: [disa.stig_spt@mail.mil.](mailto:disa.stig_spt@mail.mil)



### RHEL-06-000526

__Vuln ID__ V-38437

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50237r1_rule

__STIG ID__ RHEL-06-000526

__Rule Title__

`Automated file system mounting tools must not be enabled unless needed.`

__Discussion__

```
All filesystems that are required for the successful operation of the system should be explicitly listed in "/etc/fstab" by an administrator. New filesystems should not be arbitrarily introduced via the automounter.

The "autofs" daemon mounts and unmounts filesystems, such as user home directories shared via NFS, on demand. In addition, autofs can be used to handle removable media, and the default configuration provides the cdrom device as "/misc/cd". However, this method of providing access to removable media is not common, so autofs can almost always be disabled if NFS is not in use. Even if NFS is required, it is almost always possible to configure filesystem mounts statically by editing "/etc/fstab" rather than relying on the automounter. 
```

__Check Content__

```
To verify the "autofs" service is disabled, run the following command: 

chkconfig --list autofs

If properly configured, the output should be the following: 

autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Verify the "autofs" service is not running:

# service autofs status

If the autofs service is enabled or running, this is a finding.
```

__Fix Text__

```
If the "autofs" service is not needed to dynamically mount NFS filesystems or removable media, disable the service for all runlevels: 

# chkconfig --level 0123456 autofs off

Stop the service if it is already running: 

# service autofs stop
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000525

__Vuln ID__ V-38438

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50238r3_rule

__STIG ID__ RHEL-06-000525

__Rule Title__

`Auditing must be enabled at boot by setting a kernel parameter.`

__Discussion__

```
Each process on the system carries an "auditable" flag which indicates whether its activities can be audited. Although "auditd" takes care of enabling this for all processes which launch after it does, adding the kernel argument ensures it is set for every process during boot.
```

__Check Content__

```
Inspect the kernel boot arguments (which follow the word "kernel") in "/boot/grub/grub.conf". If they include "audit=1", then auditing is enabled at boot time. 

If auditing is not enabled at boot time, this is a finding.
```

__Fix Text__

```
To ensure all processes can be audited, even those which start prior to the audit daemon, add the argument "audit=1" to the kernel line in "/boot/grub/grub.conf", in the manner below:

kernel /vmlinuz-version ro vga=ext root=/dev/VolGroup00/LogVol00 rhgb quiet audit=1

UEFI systems may prepend "/boot" to the "/vmlinuz-version" argument. 
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000524

__Vuln ID__ V-38439

__Severity__ medium

__Group Title__ SRG-OS-000001

__Rule ID__ SV-50239r1_rule

__STIG ID__ RHEL-06-000524

__Rule Title__

`The system must provide automated support for account management functions.`

__Discussion__

```
A comprehensive account management process that includes automation helps to ensure the accounts designated as requiring attention are consistently and promptly addressed. Enterprise environments make user account management challenging and complex. A user management process requiring administrators to manually address account management functions adds risk of potential oversight.
```

__Check Content__

```
Interview the SA to determine if there is an automated system for managing user accounts, preferably integrated with an existing enterprise user management system.

If there is not, this is a finding.
```

__Fix Text__

```
Implement an automated system for managing user accounts that minimizes the risk of errors, either intentional or deliberate.  If possible, this system should integrate with an existing enterprise user management system, such as, one based Active Directory or Kerberos.
```

__CCI__

```
CCI-000015
The organization employs automated mechanisms to support the information system account management functions.
NIST SP 800-53 :: AC-2 (1)
NIST SP 800-53A :: AC-2 (1).1
NIST SP 800-53 Revision 4 :: AC-2 (1)


```


### RHEL-06-000036

__Vuln ID__ V-38443

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50243r1_rule

__STIG ID__ RHEL-06-000036

__Rule Title__

`The /etc/gshadow file must be owned by root.`

__Discussion__

```
The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
```

__Check Content__

```
To check the ownership of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the owner of "/etc/gshadow", run the command: 

# chown root /etc/gshadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000523

__Vuln ID__ V-38444

__Severity__ medium

__Group Title__ SRG-OS-000231

__Rule ID__ SV-50244r2_rule

__STIG ID__ RHEL-06-000523

__Rule Title__

`The systems local IPv6 firewall must implement a deny-all, allow-by-exception policy for inbound packets.`

__Discussion__

```
In "ip6tables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
```

__Check Content__

```
If IPv6 is disabled, this is not applicable.

Inspect the file "/etc/sysconfig/ip6tables" to determine the default policy for the INPUT chain. It should be set to DROP:

# grep ":INPUT" /etc/sysconfig/ip6tables

If the default policy for the INPUT chain is not set to DROP, this is a finding. 
```

__Fix Text__

```
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/ip6tables": 

:INPUT DROP [0:0]

Restart the IPv6 firewall:

# service ip6tables restart
```

__CCI__

```
CCI-000066
The organization enforces requirements for remote connections to the information system.
NIST SP 800-53 :: AC-17 e
NIST SP 800-53A :: AC-17.1 (v)


```


### RHEL-06-000522

__Vuln ID__ V-38445

__Severity__ medium

__Group Title__ SRG-OS-000057

__Rule ID__ SV-50245r2_rule

__STIG ID__ RHEL-06-000522

__Rule Title__

`Audit log files must be group-owned by root.`

__Discussion__

```
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
```

__Check Content__

```
Run the following command to check the group owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n

Audit logs must be group-owned by root. 
If they are not, this is a finding.
```

__Fix Text__

```
Change the group owner of the audit log files with the following command: 

# chgrp root [audit_file]
```

__CCI__

```
CCI-000162
The information system protects audit information from unauthorized access.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000521

__Vuln ID__ V-38446

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50246r2_rule

__STIG ID__ RHEL-06-000521

__Rule Title__

`The mail system must forward all mail for root to one or more system administrators.`

__Discussion__

```
A number of system services utilize email messages sent to the root user to notify system administrators of active or impending issues.  These messages must be forwarded to at least one monitored email address.
```

__Check Content__

```
Find the list of alias maps used by the Postfix mail server:

# postconf alias_maps

Query the Postfix alias maps for an alias for "root":

# postmap -q root hash:/etc/aliases

If there are no aliases configured for root that forward to a monitored email address, this is a finding.
```

__Fix Text__

```
Set up an alias for root that forwards to a monitored email address:

# echo "root: <system.administrator>@mail.mil" >> /etc/aliases
# newaliases
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000519

__Vuln ID__ V-38447

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50247r3_rule

__STIG ID__ RHEL-06-000519

__Rule Title__

`The system package management tool must verify contents of all files associated with packages.`

__Discussion__

```
The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.
```

__Check Content__

```
The following command will list which files on the system have file hashes different from what is expected by the RPM database. 

# rpm -Va | awk '$1 ~ /..5/ && $2 != "c"'


If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding.

```

__Fix Text__

```
The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -Va | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories. 

rpm -Uvh [affected_package]

OR 

yum reinstall [affected_package]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000037

__Vuln ID__ V-38448

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50248r1_rule

__STIG ID__ RHEL-06-000037

__Rule Title__

`The /etc/gshadow file must be group-owned by root.`

__Discussion__

```
The "/etc/gshadow" file contains group password hashes. Protection of this file is critical for system security.
```

__Check Content__

```
To check the group ownership of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the group owner of "/etc/gshadow", run the command: 

# chgrp root /etc/gshadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000038

__Vuln ID__ V-38449

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50249r1_rule

__STIG ID__ RHEL-06-000038

__Rule Title__

`The /etc/gshadow file must have mode 0000.`

__Discussion__

```
The /etc/gshadow file contains group password hashes. Protection of this file is critical for system security.
```

__Check Content__

```
To check the permissions of "/etc/gshadow", run the command: 

$ ls -l /etc/gshadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the permissions of "/etc/gshadow", run the command: 

# chmod 0000 /etc/gshadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000039

__Vuln ID__ V-38450

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50250r1_rule

__STIG ID__ RHEL-06-000039

__Rule Title__

`The /etc/passwd file must be owned by root.`

__Discussion__

```
The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.
```

__Check Content__

```
To check the ownership of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the owner of "/etc/passwd", run the command: 

# chown root /etc/passwd
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000040

__Vuln ID__ V-38451

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50251r1_rule

__STIG ID__ RHEL-06-000040

__Rule Title__

`The /etc/passwd file must be group-owned by root.`

__Discussion__

```
The "/etc/passwd" file contains information about the users that are configured on the system. Protection of this file is critical for system security.
```

__Check Content__

```
To check the group ownership of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the group owner of "/etc/passwd", run the command: 

# chgrp root /etc/passwd
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000518

__Vuln ID__ V-38452

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50252r2_rule

__STIG ID__ RHEL-06-000518

__Rule Title__

`The system package management tool must verify permissions on all files and directories associated with packages.`

__Discussion__

```
Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which files and directories on the system have permissions different from what is expected by the RPM database: 

# rpm -Va  | grep '^.M'

If there is any output, for each file or directory found, find the associated RPM package and compare the RPM-expected permissions with the actual permissions on the file or directory:

# rpm -qf [file or directory name]
# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" [package] | grep  [filename]
# ls -dlL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.
```

__Fix Text__

```
The RPM package management system can restore file access permissions of package files and directories. The following command will update permissions on files and directories with permissions different from what is expected by the RPM database: 

# rpm --setperms [package]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000517

__Vuln ID__ V-38453

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50253r2_rule

__STIG ID__ RHEL-06-000517

__Rule Title__

`The system package management tool must verify group-ownership on all files and directories associated with packages.`

__Discussion__

```
Group-ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which files on the system have group-ownership different from what is expected by the RPM database: 

# rpm -Va | grep '^......G'


If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding.

```

__Fix Text__

```
The RPM package management system can restore group-ownership of the package files and directories. The following command will update files and directories with group-ownership different from what is expected by the RPM database: 

# rpm -qf [file or directory name]
# rpm --setugids [package]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000516

__Vuln ID__ V-38454

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50254r2_rule

__STIG ID__ RHEL-06-000516

__Rule Title__

`The system package management tool must verify ownership on all files and directories associated with packages.`

__Discussion__

```
Ownership of system binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which files on the system have ownership different from what is expected by the RPM database: 

# rpm -Va | grep '^.....U'


If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.

If any output has not been documented with the ISSO, this is a finding.

```

__Fix Text__

```
The RPM package management system can restore ownership of package files and directories. The following command will update files and directories with ownership different from what is expected by the RPM database: 

# rpm -qf [file or directory name]
# rpm --setugids [package]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000001

__Vuln ID__ V-38455

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50255r1_rule

__STIG ID__ RHEL-06-000001

__Rule Title__

`The system must use a separate file system for /tmp.`

__Discussion__

```
The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs which use it.
```

__Check Content__

```
Run the following command to determine if "/tmp" is on its own partition or logical volume: 

$ mount | grep "on /tmp "

If "/tmp" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
```

__Fix Text__

```
The "/tmp" directory is a world-writable directory used for temporary file storage. Ensure it has its own partition or logical volume at installation time, or migrate it using LVM.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000002

__Vuln ID__ V-38456

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50256r1_rule

__STIG ID__ RHEL-06-000002

__Rule Title__

`The system must use a separate file system for /var.`

__Discussion__

```
Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs which use it. It is not uncommon for the "/var" directory to contain world-writable directories, installed by other software packages.
```

__Check Content__

```
Run the following command to determine if "/var" is on its own partition or logical volume: 

$ mount | grep "on /var "

If "/var" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
```

__Fix Text__

```
The "/var" directory is used by daemons and other system services to store frequently-changing data. Ensure that "/var" has its own partition or logical volume at installation time, or migrate it using LVM.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000041

__Vuln ID__ V-38457

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50257r1_rule

__STIG ID__ RHEL-06-000041

__Rule Title__

`The /etc/passwd file must have mode 0644 or less permissive.`

__Discussion__

```
If the "/etc/passwd" file is writable by a group-owner or the world the risk of its compromise is increased. The file contains the list of accounts on the system and associated information, and protection of this file is critical for system security.
```

__Check Content__

```
To check the permissions of "/etc/passwd", run the command: 

$ ls -l /etc/passwd

If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the permissions of "/etc/passwd", run the command: 

# chmod 0644 /etc/passwd
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000042

__Vuln ID__ V-38458

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50258r1_rule

__STIG ID__ RHEL-06-000042

__Rule Title__

`The /etc/group file must be owned by root.`

__Discussion__

```
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
```

__Check Content__

```
To check the ownership of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the owner of "/etc/group", run the command: 

# chown root /etc/group
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000043

__Vuln ID__ V-38459

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50259r1_rule

__STIG ID__ RHEL-06-000043

__Rule Title__

`The /etc/group file must be group-owned by root.`

__Discussion__

```
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
```

__Check Content__

```
To check the group ownership of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the group owner of "/etc/group", run the command: 

# chgrp root /etc/group
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000515

__Vuln ID__ V-38460

__Severity__ low

__Group Title__ SRG-OS-000104

__Rule ID__ SV-50260r1_rule

__STIG ID__ RHEL-06-000515

__Rule Title__

`The NFS server must not have the all_squash option enabled.`

__Discussion__

```
The "all_squash" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID.
```

__Check Content__

```
If the NFS server is read-only, in support of unrestricted access to organizational content, this is not applicable.

The related "root_squash" option provides protection against remote administrator-level access to NFS server content.  Its use is not a finding.

To verify the "all_squash" option has been disabled, run the following command:

# grep all_squash /etc/exports


If there is output, this is a finding.
```

__Fix Text__

```
Remove any instances of the "all_squash" option from the file "/etc/exports".  Restart the NFS daemon for the changes to take effect.

# service nfs restart
```

__CCI__

```
CCI-000764
The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).
NIST SP 800-53 :: IA-2
NIST SP 800-53A :: IA-2.1
NIST SP 800-53 Revision 4 :: IA-2


```


### RHEL-06-000044

__Vuln ID__ V-38461

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50261r1_rule

__STIG ID__ RHEL-06-000044

__Rule Title__

`The /etc/group file must have mode 0644 or less permissive.`

__Discussion__

```
The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.
```

__Check Content__

```
To check the permissions of "/etc/group", run the command: 

$ ls -l /etc/group

If properly configured, the output should indicate the following permissions: "-rw-r--r--" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the permissions of "/etc/group", run the command: 

# chmod 644 /etc/group
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000003

__Vuln ID__ V-38463

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50263r1_rule

__STIG ID__ RHEL-06-000003

__Rule Title__

`The system must use a separate file system for /var/log.`

__Discussion__

```
Placing "/var/log" in its own partition enables better separation between log files and other files in "/var/".
```

__Check Content__

```
Run the following command to determine if "/var/log" is on its own partition or logical volume: 

$ mount | grep "on /var/log "

If "/var/log" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
```

__Fix Text__

```
System logs are stored in the "/var/log" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it using LVM.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000511

__Vuln ID__ V-38464

__Severity__ medium

__Group Title__ SRG-OS-000047

__Rule ID__ SV-50264r1_rule

__STIG ID__ RHEL-06-000511

__Rule Title__

`The audit system must take appropriate action when there are disk errors on the audit storage volume.`

__Discussion__

```
Taking appropriate action in case of disk errors will minimize the possibility of losing audit records.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when disk errors occur:

# grep disk_error_action /etc/audit/auditd.conf
disk_error_action = [ACTION]


If the system is configured to "suspend" when disk errors occur or "ignore" them, this is a finding.
```

__Fix Text__

```
Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

disk_error_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"exec"
"suspend"
"single"
"halt"


Set this to "syslog", "exec", "single", or "halt".
```

__CCI__

```
CCI-000140
The information system takes organization-defined actions upon audit failure (e.g., shut down information system, overwrite oldest audit records, stop generating audit records).
NIST SP 800-53 :: AU-5 b
NIST SP 800-53A :: AU-5.1 (iv)
NIST SP 800-53 Revision 4 :: AU-5 b


```


### RHEL-06-000045

__Vuln ID__ V-38465

__Severity__ medium

__Group Title__ SRG-OS-000259

__Rule ID__ SV-50265r3_rule

__STIG ID__ RHEL-06-000045

__Rule Title__

`Library files must have mode 0755 or less permissive.`

__Discussion__

```
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Restrictive permissions are necessary to protect the integrity of the system.
```

__Check Content__

```
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64


Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable. To find shared libraries that are group-writable or world-writable, run the following command for each directory [DIR] which contains shared libraries: 

$ find -L [DIR] -perm /022 -type f


If any of these files (excluding broken symlinks) are group-writable or world-writable, this is a finding.
```

__Fix Text__

```
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command: 

# chmod go-w [FILE]
```

__CCI__

```
CCI-001499
The organization limits privileges to change software resident within software libraries.
NIST SP 800-53 :: CM-5 (6)
NIST SP 800-53A :: CM-5 (6).1
NIST SP 800-53 Revision 4 :: CM-5 (6)


```


### RHEL-06-000046

__Vuln ID__ V-38466

__Severity__ medium

__Group Title__ SRG-OS-000259

__Rule ID__ SV-50266r4_rule

__STIG ID__ RHEL-06-000046

__Rule Title__

`Library files must be owned by a system account.`

__Discussion__

```
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.
```

__Check Content__

```
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64
/usr/local/lib
/usr/local/lib64

Kernel modules, which can be added to the kernel during runtime, are stored in "/lib/modules". All files in these directories should not be group-writable or world-writable.  To find shared libraries that are not owned by "root" and do not match what is expected by the RPM, run the following command:

for i in /lib /lib64 /usr/lib /usr/lib64
do
  for j in `find -L $i \! -user root`
  do
    rpm -V -f $j | grep '^.....U'
  done
done


If the command returns any results, this is a finding.
```

__Fix Text__

```
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default: 

/lib
/lib64
/usr/lib
/usr/lib64
/usr/local/lib 
/usr/local/lib64

If any file in these directories is found to be owned by a user other than "root" and does not match what is expected by the RPM, correct its ownership by running one of the following commands: 


# rpm --setugids [PACKAGE_NAME]

Or

# chown root [FILE]
```

__CCI__

```
CCI-001499
The organization limits privileges to change software resident within software libraries.
NIST SP 800-53 :: CM-5 (6)
NIST SP 800-53A :: CM-5 (6).1
NIST SP 800-53 Revision 4 :: CM-5 (6)


```


### RHEL-06-000004

__Vuln ID__ V-38467

__Severity__ low

__Group Title__ SRG-OS-000044

__Rule ID__ SV-50267r1_rule

__STIG ID__ RHEL-06-000004

__Rule Title__

`The system must use a separate file system for the system audit data path.`

__Discussion__

```
Placing "/var/log/audit" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.
```

__Check Content__

```
Run the following command to determine if "/var/log/audit" is on its own partition or logical volume: 

$ mount | grep "on /var/log/audit "

If "/var/log/audit" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
```

__Fix Text__

```
Audit logs are stored in the "/var/log/audit" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon.
```

__CCI__

```
CCI-000137
The organization allocates audit record storage capacity.
NIST SP 800-53 :: AU-4
NIST SP 800-53A :: AU-4.1 (i)


```


### RHEL-06-000510

__Vuln ID__ V-38468

__Severity__ medium

__Group Title__ SRG-OS-000047

__Rule ID__ SV-50268r1_rule

__STIG ID__ RHEL-06-000510

__Rule Title__

`The audit system must take appropriate action when the audit storage volume is full.`

__Discussion__

```
Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to take appropriate action when the audit storage volume is full:

# grep disk_full_action /etc/audit/auditd.conf
disk_full_action = [ACTION]


If the system is configured to "suspend" when the volume is full or "ignore" that it is full, this is a finding.
```

__Fix Text__

```
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

disk_full_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"exec"
"suspend"
"single"
"halt"


Set this to "syslog", "exec", "single", or "halt".
```

__CCI__

```
CCI-000140
The information system takes organization-defined actions upon audit failure (e.g., shut down information system, overwrite oldest audit records, stop generating audit records).
NIST SP 800-53 :: AU-5 b
NIST SP 800-53A :: AU-5.1 (iv)
NIST SP 800-53 Revision 4 :: AU-5 b


```


### RHEL-06-000047

__Vuln ID__ V-38469

__Severity__ medium

__Group Title__ SRG-OS-000259

__Rule ID__ SV-50269r3_rule

__STIG ID__ RHEL-06-000047

__Rule Title__

`All system command files must have mode 755 or less permissive.`

__Discussion__

```
System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted.
```

__Check Content__

```
System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are group-writable or world-writable, run the following command for each directory [DIR] which contains system executables: 

$ find -L [DIR] -perm /022 -type f

If any system executables are found to be group-writable or world-writable, this is a finding.
```

__Fix Text__

```
System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command: 

# chmod go-w [FILE]
```

__CCI__

```
CCI-001499
The organization limits privileges to change software resident within software libraries.
NIST SP 800-53 :: CM-5 (6)
NIST SP 800-53A :: CM-5 (6).1
NIST SP 800-53 Revision 4 :: CM-5 (6)


```


### RHEL-06-000005

__Vuln ID__ V-38470

__Severity__ medium

__Group Title__ SRG-OS-000045

__Rule ID__ SV-50270r2_rule

__STIG ID__ RHEL-06-000005

__Rule Title__

`The audit system must alert designated staff members when the audit storage volume approaches capacity.`

__Discussion__

```
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low: 

# grep space_left_action /etc/audit/auditd.conf
space_left_action = email


If the system is not configured to send an email to the system administrator when disk space is starting to run low, this is a finding.  The "syslog" option is acceptable when it can be demonstrated that the local log management infrastructure notifies an appropriate administrator in a timely manner.
```

__Fix Text__

```
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [ACTION] appropriately: 

space_left_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"email"
"exec"
"suspend"
"single"
"halt"


Set this to "email" (instead of the default, which is "suspend") as it is more likely to get prompt attention.  The "syslog" option is acceptable, provided the local log management infrastructure notifies an appropriate administrator in a timely manner.

RHEL-06-000521 ensures that the email generated through the operation "space_left_action" will be sent to an administrator.
```

__CCI__

```
CCI-000138
The organization configures auditing to reduce the likelihood of storage capacity being exceeded.
NIST SP 800-53 :: AU-4
NIST SP 800-53A :: AU-4.1 (ii)


```


### RHEL-06-000509

__Vuln ID__ V-38471

__Severity__ low

__Group Title__ SRG-OS-000043

__Rule ID__ SV-50271r1_rule

__STIG ID__ RHEL-06-000509

__Rule Title__

`The system must forward audit records to the syslog service.`

__Discussion__

```
The auditd service does not include the ability to send audit records to a centralized server for management directly.  It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server.
```

__Check Content__

```
Verify the audispd plugin is active:

# grep active /etc/audisp/plugins.d/syslog.conf

If the "active" setting is missing or set to "no", this is a finding.
```

__Fix Text__

```
Set the "active" line in "/etc/audisp/plugins.d/syslog.conf" to "yes".  Restart the auditd process.

# service auditd restart
```

__CCI__

```
CCI-000136
The organization centrally manages the content of audit records generated by organization defined information system components.
NIST SP 800-53 :: AU-3 (2)
NIST SP 800-53A :: AU-3 (2).1 (ii)


```


### RHEL-06-000048

__Vuln ID__ V-38472

__Severity__ medium

__Group Title__ SRG-OS-000259

__Rule ID__ SV-50272r1_rule

__STIG ID__ RHEL-06-000048

__Rule Title__

`All system command files must be owned by root.`

__Discussion__

```
System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.
```

__Check Content__

```
System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by "root", run the following command for each directory [DIR] which contains system executables: 

$ find -L [DIR] \! -user root


If any system executables are found to not be owned by root, this is a finding.
```

__Fix Text__

```
System executables are stored in the following directories by default: 

/bin
/usr/bin
/usr/local/bin
/sbin
/usr/sbin
/usr/local/sbin

If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command: 

# chown root [FILE]
```

__CCI__

```
CCI-001499
The organization limits privileges to change software resident within software libraries.
NIST SP 800-53 :: CM-5 (6)
NIST SP 800-53A :: CM-5 (6).1
NIST SP 800-53 Revision 4 :: CM-5 (6)


```


### RHEL-06-000007

__Vuln ID__ V-38473

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50273r1_rule

__STIG ID__ RHEL-06-000007

__Rule Title__

`The system must use a separate file system for user home directories.`

__Discussion__

```
Ensuring that "/home" is mounted on its own partition enables the setting of more restrictive mount options, and also helps ensure that users cannot trivially fill partitions used for log or audit data storage.
```

__Check Content__

```
Run the following command to determine if "/home" is on its own partition or logical volume: 

$ mount | grep "on /home "

If "/home" has its own partition or volume group, a line will be returned. 
If no line is returned, this is a finding.
```

__Fix Text__

```
If user home directories will be stored locally, create a separate partition for "/home" at installation time (or migrate it later using LVM). If "/home" will be mounted from another system such as an NFS server, then creating a separate partition is not necessary at installation time, and the mountpoint can instead be configured later.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000508

__Vuln ID__ V-38474

__Severity__ low

__Group Title__ SRG-OS-000030

__Rule ID__ SV-50274r2_rule

__STIG ID__ RHEL-06-000508

__Rule Title__

`The system must allow locking of graphical desktop sessions.`

__Discussion__

```
The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

Verify the keybindings for the Gnome screensaver:

# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver

If no output is visible, this is a finding.
```

__Fix Text__

```
Run the following command to set the Gnome desktop keybinding for locking the screen:

# gconftool-2
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome_settings_daemon/keybindings/screensaver "<Control><Alt>l"

Another keyboard sequence may be substituted for "<Control><Alt>l", which is the default for the Gnome desktop.
```

__CCI__

```
CCI-000058
The information system provides the capability for users to directly initiate session lock mechanisms.
NIST SP 800-53 :: AC-11 a
NIST SP 800-53A :: AC-11
NIST SP 800-53 Revision 4 :: AC-11 a


```


### RHEL-06-000050

__Vuln ID__ V-38475

__Severity__ medium

__Group Title__ SRG-OS-000078

__Rule ID__ SV-50275r3_rule

__STIG ID__ RHEL-06-000050

__Rule Title__

`The system must require passwords to contain a minimum of 15 characters.`

__Discussion__

```
Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.

While it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).
```

__Check Content__

```
To check the minimum password length, run the command: 

$ grep PASS_MIN_LEN /etc/login.defs

The DoD requirement is "15". 

If it is not set to the required value, this is a finding.

$ grep -E �pam_cracklib.so.*minlen� /etc/pam.d/*

If no results are returned, this is not a finding.

If any results are returned and are not set to "15" or greater, this is a finding.

```

__Fix Text__

```
To specify password length requirements for new accounts, edit the file "/etc/login.defs" and add or correct the following lines: 

PASS_MIN_LEN 15

The DoD requirement is "15". If a program consults "/etc/login.defs" and also another PAM module (such as "pam_cracklib") during a password change operation, then the most restrictive must be satisfied.
```

__CCI__

```
CCI-000205
The information system enforces minimum password length.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (i)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)


```


### RHEL-06-000008

__Vuln ID__ V-38476

__Severity__ high

__Group Title__ SRG-OS-000090

__Rule ID__ SV-50276r3_rule

__STIG ID__ RHEL-06-000008

__Rule Title__

`Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.`

__Discussion__

```
The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat. 
```

__Check Content__

```
To ensure that the GPG keys are installed, run:

$ rpm -q gpg-pubkey

The command should return the strings below:

gpg-pubkey-fd431d51-4ae0493b
gpg-pubkey-2fa658e0-45700c69

If the Red Hat GPG Keys are not installed, this is a finding.
```

__Fix Text__

```
To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG keys must be installed properly. To install the Red Hat GPG keys, run:

# rhn_register

If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG keys from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in "/media/cdrom", use the following command as the root user to import them into the keyring:

# rpm --import /media/cdrom/RPM-GPG-KEY
```

__CCI__

```
CCI-000352
The information system prevents the installation of organization defined critical software programs that are not signed with a certificate that is recognized and approved by the organization.
NIST SP 800-53 :: CM-5 (3)
NIST SP 800-53A :: CM-5 (3).1 (ii)


```


### RHEL-06-000051

__Vuln ID__ V-38477

__Severity__ medium

__Group Title__ SRG-OS-000075

__Rule ID__ SV-50277r1_rule

__STIG ID__ RHEL-06-000051

__Rule Title__

`Users must not be able to change passwords more than once every 24 hours.`

__Discussion__

```
Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement.
```

__Check Content__

```
To check the minimum password age, run the command: 

$ grep PASS_MIN_DAYS /etc/login.defs

The DoD requirement is 1. 
If it is not set to the required value, this is a finding.
```

__Fix Text__

```
To specify password minimum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_MIN_DAYS [DAYS]

A value of 1 day is considered sufficient for many environments. The DoD requirement is 1.
```

__CCI__

```
CCI-000198
The information system enforces minimum password lifetime restrictions.
NIST SP 800-53 :: IA-5 (1) (d)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (d)


```


### RHEL-06-000009

__Vuln ID__ V-38478

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50278r2_rule

__STIG ID__ RHEL-06-000009

__Rule Title__

`The Red Hat Network Service (rhnsd) service must not be running, unless using RHN or an RHN Satellite.`

__Discussion__

```
Although systems management and patching is extremely important to system security, management by a system outside the enterprise enclave is not desirable for some environments. However, if the system is being managed by RHN or RHN Satellite Server the "rhnsd" daemon can remain on.
```

__Check Content__

```
If the system uses RHN or an RHN Satellite, this is not applicable.

To check that the "rhnsd" service is disabled in system boot configuration, run the following command: 

# chkconfig "rhnsd" --list

Output should indicate the "rhnsd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rhnsd" --list
"rhnsd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rhnsd" is disabled through current runtime configuration: 

# service rhnsd status

If the service is disabled the command will return the following output: 

rhnsd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The Red Hat Network service automatically queries Red Hat Network servers to determine whether there are any actions that should be executed, such as package updates. This only occurs if the system was registered to an RHN server or satellite and managed as such. The "rhnsd" service can be disabled with the following commands: 

# chkconfig rhnsd off
# service rhnsd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000053

__Vuln ID__ V-38479

__Severity__ medium

__Group Title__ SRG-OS-000076

__Rule ID__ SV-50279r1_rule

__STIG ID__ RHEL-06-000053

__Rule Title__

`User passwords must be changed at least every 60 days.`

__Discussion__

```
Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.
```

__Check Content__

```
To check the maximum password age, run the command: 

$ grep PASS_MAX_DAYS /etc/login.defs

The DoD requirement is 60. 
If it is not set to the required value, this is a finding.
```

__Fix Text__

```
To specify password maximum age for new accounts, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_MAX_DAYS [DAYS]

The DoD requirement is 60.
```

__CCI__

```
CCI-000199
The information system enforces maximum password lifetime restrictions.
NIST SP 800-53 :: IA-5 (1) (d)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (d)


```


### RHEL-06-000054

__Vuln ID__ V-38480

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50280r1_rule

__STIG ID__ RHEL-06-000054

__Rule Title__

`Users must be warned 7 days in advance of password expiration.`

__Discussion__

```
Setting the password warning age enables users to make the change at a practical time.
```

__Check Content__

```
To check the password warning age, run the command: 

$ grep PASS_WARN_AGE /etc/login.defs

The DoD requirement is 7. 
If it is not set to the required value, this is a finding.
```

__Fix Text__

```
To specify how many days prior to password expiration that a warning will be issued to users, edit the file "/etc/login.defs" and add or correct the following line, replacing [DAYS] appropriately: 

PASS_WARN_AGE [DAYS]

The DoD requirement is 7.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000011

__Vuln ID__ V-38481

__Severity__ medium

__Group Title__ SRG-OS-000191

__Rule ID__ SV-50281r1_rule

__STIG ID__ RHEL-06-000011

__Rule Title__

`System security patches and updates must be installed and up-to-date.`

__Discussion__

```
Installing software updates is a fundamental mitigation against the exploitation of publicly-known vulnerabilities.
```

__Check Content__

```
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server which provides updates, invoking the following command will indicate if updates are available: 

# yum check-update

If the system is not configured to update from one of these sources, run the following command to list when each package was last updated: 

$ rpm -qa -last

Compare this to Red Hat Security Advisories (RHSA) listed at https://access.redhat.com/security/updates/active/ to determine whether the system is missing applicable security and bugfix  updates. 
If updates are not installed, this is a finding.
```

__Fix Text__

```
If the system is joined to the Red Hat Network, a Red Hat Satellite Server, or a yum server, run the following command to install updates: 

# yum update

If the system is not configured to use one of these sources, updates (in the form of RPM packages) can be manually downloaded from the Red Hat Network and installed using "rpm".
```

__CCI__

```
CCI-001233
The organization employs automated mechanisms on an organization-defined frequency to determine the state of information system components with regard to flaw remediation.
NIST SP 800-53 :: SI-2 (2)
NIST SP 800-53A :: SI-2 (2).1 (ii)
NIST SP 800-53 Revision 4 :: SI-2 (2)


```


### RHEL-06-000056

__Vuln ID__ V-38482

__Severity__ low

__Group Title__ SRG-OS-000071

__Rule ID__ SV-50282r1_rule

__STIG ID__ RHEL-06-000056

__Rule Title__

`The system must require passwords to contain at least one numeric character.`

__Discussion__

```
Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.
```

__Check Content__

```
To check how many digits are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "dcredit" parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as "dcredit=-1". 
If dcredit is not found or not set to the required value, this is a finding.
```

__Fix Text__

```
The pam_cracklib module's "dcredit" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit. Add "dcredit=-1" after pam_cracklib.so to require use of a digit in passwords.
```

__CCI__

```
CCI-000194
The information system enforces password complexity by the minimum number of numeric characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)


```


### RHEL-06-000013

__Vuln ID__ V-38483

__Severity__ medium

__Group Title__ SRG-OS-000103

__Rule ID__ SV-50283r1_rule

__STIG ID__ RHEL-06-000013

__Rule Title__

`The system package management tool must cryptographically verify the authenticity of system software packages during installation.`

__Discussion__

```
Ensuring the validity of packages' cryptographic signatures prior to installation ensures the provenance of the software and protects against malicious tampering.
```

__Check Content__

```
To determine whether "yum" is configured to use "gpgcheck", inspect "/etc/yum.conf" and ensure the following appears in the "[main]" section: 

gpgcheck=1

A value of "1" indicates that "gpgcheck" is enabled. Absence of a "gpgcheck" line or a setting of "0" indicates that it is disabled. 
If GPG checking is not enabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
```

__Fix Text__

```
The "gpgcheck" option should be used to ensure checking of an RPM package's signature always occurs prior to its installation. To configure yum to check package signatures before installing them, ensure the following line appears in "/etc/yum.conf" in the "[main]" section: 

gpgcheck=1
```

__CCI__

```
CCI-000663
The organization (or information system) enforces explicit rules governing the installation of software by users.
NIST SP 800-53 :: SA-7
NIST SP 800-53A :: SA-7.1 (ii)


```


### RHEL-06-000507

__Vuln ID__ V-38484

__Severity__ medium

__Group Title__ SRG-OS-000025

__Rule ID__ SV-50285r2_rule

__STIG ID__ RHEL-06-000507

__Rule Title__

`The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.`

__Discussion__

```
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.

At ssh login, a user must be presented with the last successful login date and time.
```

__Check Content__

```
Verify the value associated with the "PrintLastLog" keyword in /etc/ssh/sshd_config:

# grep -i "^PrintLastLog" /etc/ssh/sshd_config

If the "PrintLastLog" keyword is not present, this is not a finding.  If the value is not set to "yes", this is a finding.
```

__Fix Text__

```
Update the "PrintLastLog" keyword to "yes" in /etc/ssh/sshd_config:

PrintLastLog yes

While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last logon date and time, it is preferred to have the value explicitly documented.
```

__CCI__

```
CCI-000052
The information system notifies the user, upon successful logon (access) to the system, of the date and time of the last logon (access).
NIST SP 800-53 :: AC-9
NIST SP 800-53A :: AC-9.1
NIST SP 800-53 Revision 4 :: AC-9


```


### RHEL-06-000505

__Vuln ID__ V-38486

__Severity__ medium

__Group Title__ SRG-OS-000100

__Rule ID__ SV-50287r1_rule

__STIG ID__ RHEL-06-000505

__Rule Title__

`The operating system must conduct backups of system-level information contained in the information system per organization defined frequency to conduct backups that are consistent with recovery time and recovery point objectives.`

__Discussion__

```
Operating system backup is a critical step in maintaining data assurance and availability. System-level information includes system-state information, operating system and application software, and licenses. Backups must be consistent with organizational recovery time and recovery point objectives.
```

__Check Content__

```
Ask an administrator if a process exists to back up OS data from the system, including configuration data. 

If such a process does not exist, this is a finding.
```

__Fix Text__

```
Procedures to back up OS data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.

Implement a process whereby OS data is backed up from the system in accordance with local policies.
```

__CCI__

```
CCI-000537
The organization conducts backups of system-level information contained in the information system per organization-defined frequency that is consistent with recovery time and recovery point objectives.
NIST SP 800-53 :: CP-9 (b)
NIST SP 800-53A :: CP-9.1 (v)
NIST SP 800-53 Revision 4 :: CP-9 (b)


```


### RHEL-06-000015

__Vuln ID__ V-38487

__Severity__ low

__Group Title__ SRG-OS-000103

__Rule ID__ SV-50288r1_rule

__STIG ID__ RHEL-06-000015

__Rule Title__

`The system package management tool must cryptographically verify the authenticity of all software packages during installation.`

__Discussion__

```
Ensuring all packages' cryptographic signatures are valid prior to installation ensures the provenance of the software and protects against malicious tampering.
```

__Check Content__

```
To determine whether "yum" has been configured to disable "gpgcheck" for any repos, inspect all files in "/etc/yum.repos.d" and ensure the following does not appear in any sections: 

gpgcheck=0

A value of "0" indicates that "gpgcheck" has been disabled for that repo. 
If GPG checking is disabled, this is a finding.

If the "yum" system package management tool is not used to update the system, verify with the SA that installed packages are cryptographically signed.
```

__Fix Text__

```
To ensure signature checking is not disabled for any repos, remove any lines from files in "/etc/yum.repos.d" of the form: 

gpgcheck=0
```

__CCI__

```
CCI-000663
The organization (or information system) enforces explicit rules governing the installation of software by users.
NIST SP 800-53 :: SA-7
NIST SP 800-53A :: SA-7.1 (ii)


```


### RHEL-06-000504

__Vuln ID__ V-38488

__Severity__ medium

__Group Title__ SRG-OS-000099

__Rule ID__ SV-50289r1_rule

__STIG ID__ RHEL-06-000504

__Rule Title__

`The operating system must conduct backups of user-level information contained in the operating system per organization defined frequency to conduct backups consistent with recovery time and recovery point objectives.`

__Discussion__

```
Operating system backup is a critical step in maintaining data assurance and availability. User-level information is data generated by information system and/or application users. Backups shall be consistent with organizational recovery time and recovery point objectives.
```

__Check Content__

```
Ask an administrator if a process exists to back up user data from the system. 

If such a process does not exist, this is a finding.
```

__Fix Text__

```
Procedures to back up user data from the system must be established and executed. The Red Hat operating system provides utilities for automating such a process.  Commercial and open-source products are also available.

Implement a process whereby user data is backed up from the system in accordance with local policies.
```

__CCI__

```
CCI-000535
The organization conducts backups of user-level information contained in the information system per organization-defined frequency that is consistent with recovery time and recovery point objectives.
NIST SP 800-53 :: CP-9 (a)
NIST SP 800-53A :: CP-9.1 (iv)
NIST SP 800-53 Revision 4 :: CP-9 (a)


```


### RHEL-06-000016

__Vuln ID__ V-38489

__Severity__ medium

__Group Title__ SRG-OS-000232

__Rule ID__ SV-50290r1_rule

__STIG ID__ RHEL-06-000016

__Rule Title__

`A file integrity tool must be installed.`

__Discussion__

```
The AIDE package must be installed if it is to be available for integrity checking.
```

__Check Content__

```
If another file integrity tool is installed, this is not a finding.

Run the following command to determine if the "aide" package is installed: 

# rpm -q aide


If the package is not installed, this is a finding.
```

__Fix Text__

```
Install the AIDE package with the command: 

# yum install aide
```

__CCI__

```
CCI-001069
The organization employs automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.
NIST SP 800-53 :: RA-5 (7)
NIST SP 800-53A :: RA-5 (7).1 (ii)


```


### RHEL-06-000503

__Vuln ID__ V-38490

__Severity__ medium

__Group Title__ SRG-OS-000273

__Rule ID__ SV-50291r5_rule

__STIG ID__ RHEL-06-000503

__Rule Title__

`The operating system must enforce requirements for the connection of mobile devices to operating systems.`

__Discussion__

```
USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.
```

__Check Content__

```
If the system is configured to prevent the loading of the "usb-storage" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.
```

__Fix Text__

```
To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the "usb-storage" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install usb-storage /bin/true

This will prevent the "modprobe" program from loading the "usb-storage" module, but will not prevent an administrator (or another program) from using the "insmod" program to load the module manually.
```

__CCI__

```
CCI-000086
The organization enforces requirements for the connection of mobile devices to organizational information systems.
NIST SP 800-53 :: AC-19 d
NIST SP 800-53A :: AC-19.1 (iv)


```


### RHEL-06-000019

__Vuln ID__ V-38491

__Severity__ high

__Group Title__ SRG-OS-000248

__Rule ID__ SV-50292r1_rule

__STIG ID__ RHEL-06-000019

__Rule Title__

`There must be no .rhosts or hosts.equiv files on the system.`

__Discussion__

```
Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.
```

__Check Content__

```
The existence of the file "/etc/hosts.equiv" or a file named ".rhosts" inside a user home directory indicates the presence of an Rsh trust relationship. 
If these files exist, this is a finding.
```

__Fix Text__

```
The files "/etc/hosts.equiv" and "~/.rhosts" (in each user's home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location. 

# rm /etc/hosts.equiv



$ rm ~/.rhosts
```

__CCI__

```
CCI-001436
The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.
NIST SP 800-53 :: AC-17 (8)
NIST SP 800-53A :: AC-17 (8).1 (ii)


```


### RHEL-06-000027

__Vuln ID__ V-38492

__Severity__ medium

__Group Title__ SRG-OS-000109

__Rule ID__ SV-50293r1_rule

__STIG ID__ RHEL-06-000027

__Rule Title__

`The system must prevent the root account from logging in from virtual consoles.`

__Discussion__

```
Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account. 
```

__Check Content__

```
To check for virtual console entries which permit root login, run the following command: 

# grep '^vc/[0-9]' /etc/securetty

If any output is returned, then root logins over virtual console devices is permitted. 
If root login over virtual console devices is permitted, this is a finding.
```

__Fix Text__

```
To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in "/etc/securetty": 

vc/1
vc/2
vc/3
vc/4

Note:  Virtual console entries are not limited to those listed above.  Any lines starting with "vc/" followed by numerals should be removed.
```

__CCI__

```
CCI-000770
The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.
NIST SP 800-53 :: IA-2 (5) (b)
NIST SP 800-53A :: IA-2 (5).2 (ii)
NIST SP 800-53 Revision 4 :: IA-2 (5)


```


### RHEL-06-000385

__Vuln ID__ V-38493

__Severity__ medium

__Group Title__ SRG-OS-000059

__Rule ID__ SV-50294r1_rule

__STIG ID__ RHEL-06-000385

__Rule Title__

`Audit log directories must have mode 0755 or less permissive.`

__Discussion__

```
If users can delete audit logs, audit trails can be modified or destroyed.
```

__Check Content__

```
Run the following command to check the mode of the system audit directories: 

grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n

Audit directories must be mode 0755 or less permissive. 
If any are more permissive, this is a finding.
```

__Fix Text__

```
Change the mode of the audit log directories with the following command: 

# chmod go-w [audit_directory]
```

__CCI__

```
CCI-000164
The information system protects audit information from unauthorized deletion.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000028

__Vuln ID__ V-38494

__Severity__ low

__Group Title__ SRG-OS-000109

__Rule ID__ SV-50295r1_rule

__STIG ID__ RHEL-06-000028

__Rule Title__

`The system must prevent the root account from logging in from serial consoles.`

__Discussion__

```
Preventing direct root login to serial port interfaces helps ensure accountability for actions taken on the systems using the root account.
```

__Check Content__

```
To check for serial port entries which permit root login, run the following command: 

# grep '^ttyS[0-9]' /etc/securetty

If any output is returned, then root login over serial ports is permitted. 
If root login over serial ports is permitted, this is a finding.
```

__Fix Text__

```
To restrict root logins on serial ports, ensure lines of this form do not appear in "/etc/securetty": 

ttyS0
ttyS1

Note:  Serial port entries are not limited to those listed above.  Any lines starting with "ttyS" followed by numerals should be removed
```

__CCI__

```
CCI-000770
The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.
NIST SP 800-53 :: IA-2 (5) (b)
NIST SP 800-53A :: IA-2 (5).2 (ii)
NIST SP 800-53 Revision 4 :: IA-2 (5)


```


### RHEL-06-000384

__Vuln ID__ V-38495

__Severity__ medium

__Group Title__ SRG-OS-000057

__Rule ID__ SV-50296r1_rule

__STIG ID__ RHEL-06-000384

__Rule Title__

`Audit log files must be owned by root.`

__Discussion__

```
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
```

__Check Content__

```
Run the following command to check the owner of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %U:%n

Audit logs must be owned by root. 
If they are not, this is a finding.
```

__Fix Text__

```
Change the owner of the audit log files with the following command: 

# chown root [audit_file]
```

__CCI__

```
CCI-000162
The information system protects audit information from unauthorized access.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000029

__Vuln ID__ V-38496

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50297r3_rule

__STIG ID__ RHEL-06-000029

__Rule Title__

`Default operating system accounts, other than root, must be locked.`

__Discussion__

```
Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.
```

__Check Content__

```
To obtain a listing of all users and the contents of their shadow password field, run the command: 

$ awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 ":" $2}' /etc/shadow

Identify the operating system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root. 

If any default operating system account (other than root) has a valid password hash, this is a finding.
```

__Fix Text__

```
Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts. 

Disable logon access to these accounts with the command: 

# passwd -l [SYSACCT]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000030

__Vuln ID__ V-38497

__Severity__ high

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50298r2_rule

__STIG ID__ RHEL-06-000030

__Rule Title__

`The system must not have accounts configured with blank or null passwords.`

__Discussion__

```
If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.
```

__Check Content__

```
To verify that null passwords cannot be used, run the following command: 

# grep nullok /etc/pam.d/system-auth

If this produces any output, it may be possible to log into accounts with empty passwords. 
If NULL passwords can be used, this is a finding.
```

__Fix Text__

```
If an account is configured for password authentication but does not have an assigned password, it may be possible to log onto the account without authentication. Remove any instances of the "nullok" option in "/etc/pam.d/system-auth" to prevent logons with empty passwords.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000383

__Vuln ID__ V-38498

__Severity__ medium

__Group Title__ SRG-OS-000058

__Rule ID__ SV-50299r1_rule

__STIG ID__ RHEL-06-000383

__Rule Title__

`Audit log files must have mode 0640 or less permissive.`

__Discussion__

```
If users can write to audit logs, audit trails can be modified or destroyed.
```

__Check Content__

```
Run the following command to check the mode of the system audit logs: 

grep "^log_file" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %a:%n

Audit logs must be mode 0640 or less permissive. 
If any are more permissive, this is a finding.
```

__Fix Text__

```
Change the mode of the audit log files with the following command: 

# chmod 0640 [audit_file]
```

__CCI__

```
CCI-000163
The information system protects audit information from unauthorized modification.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000031

__Vuln ID__ V-38499

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50300r1_rule

__STIG ID__ RHEL-06-000031

__Rule Title__

`The /etc/passwd file must not contain password hashes.`

__Discussion__

```
The hashes for all user account passwords should be stored in the file "/etc/shadow" and never in "/etc/passwd", which is readable by all users.
```

__Check Content__

```
To check that no password hashes are stored in "/etc/passwd", run the following command: 

# awk -F: '($2 != "x") {print}' /etc/passwd

If it produces any output, then a password hash is stored in "/etc/passwd". 
If any stored hashes are found in /etc/passwd, this is a finding.
```

__Fix Text__

```
If any password hashes are stored in "/etc/passwd" (in the second field, instead of an "x"), the cause of this misconfiguration should be investigated. The account should have its password reset and the hash should be properly stored, or the account should be deleted entirely.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000032

__Vuln ID__ V-38500

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50301r2_rule

__STIG ID__ RHEL-06-000032

__Rule Title__

`The root account must be the only account having a UID of 0.`

__Discussion__

```
An account has root authority if it has a UID of 0. Multiple accounts with a UID of 0 afford more opportunity for potential intruders to guess a password for a privileged account. Proper configuration of sudo is recommended to afford multiple system administrators access to root privileges in an accountable manner.
```

__Check Content__

```
To list all password file entries for accounts with UID 0, run the following command: 

# awk -F: '($3 == 0) {print}' /etc/passwd

This should print only one line, for the user root. 
If any account other than root has a UID of 0, this is a finding.
```

__Fix Text__

```
If any account other than root has a UID of 0, this misconfiguration should be investigated and the accounts other than root should be removed or have their UID changed.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000357

__Vuln ID__ V-38501

__Severity__ medium

__Group Title__ SRG-OS-000249

__Rule ID__ SV-50302r4_rule

__STIG ID__ RHEL-06-000357

__Rule Title__

`The system must disable accounts after excessive login failures within a 15-minute interval.`

__Discussion__

```
Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks.
```

__Check Content__

```
To ensure the failed password attempt policy is configured correctly, run the following command:

$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

For each file, the output should show "fail_interval=<interval-in-seconds>" where "interval-in-seconds" is 900 (15 minutes) or greater. If the "fail_interval" parameter is not set, the default setting of 900 seconds is acceptable. If that is not the case, this is a finding. 
```

__Fix Text__

```
Utilizing "pam_faillock.so", the "fail_interval" directive configures the system to lock out accounts after a number of incorrect logon attempts. Modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
```

__CCI__

```
CCI-001452
The information system enforces the organization defined time period during which the limit of consecutive invalid access attempts by a user is counted.
NIST SP 800-53 :: AC-7 a
NIST SP 800-53A :: AC-7.1 (ii)


```


### RHEL-06-000033

__Vuln ID__ V-38502

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50303r1_rule

__STIG ID__ RHEL-06-000033

__Rule Title__

`The /etc/shadow file must be owned by root.`

__Discussion__

```
The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.
```

__Check Content__

```
To check the ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following owner: "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the owner of "/etc/shadow", run the command: 

# chown root /etc/shadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000034

__Vuln ID__ V-38503

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50304r1_rule

__STIG ID__ RHEL-06-000034

__Rule Title__

`The /etc/shadow file must be group-owned by root.`

__Discussion__

```
The "/etc/shadow" file stores password hashes. Protection of this file is critical for system security.
```

__Check Content__

```
To check the group ownership of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following group-owner. "root" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the group owner of "/etc/shadow", run the command: 

# chgrp root /etc/shadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000035

__Vuln ID__ V-38504

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50305r1_rule

__STIG ID__ RHEL-06-000035

__Rule Title__

`The /etc/shadow file must have mode 0000.`

__Discussion__

```
The "/etc/shadow" file contains the list of local system accounts and stores password hashes. Protection of this file is critical for system security. Failure to give ownership of this file to root provides the designated owner with access to sensitive information which could weaken the system security posture.
```

__Check Content__

```
To check the permissions of "/etc/shadow", run the command: 

$ ls -l /etc/shadow

If properly configured, the output should indicate the following permissions: "----------" 
If it does not, this is a finding.
```

__Fix Text__

```
To properly set the permissions of "/etc/shadow", run the command: 

# chmod 0000 /etc/shadow
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000082

__Vuln ID__ V-38511

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50312r2_rule

__STIG ID__ RHEL-06-000082

__Rule Title__

`IP forwarding for IPv4 must not be enabled, unless the system is a router.`

__Discussion__

```
IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.
```

__Check Content__

```
The status of the "net.ipv4.ip_forward" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.ip_forward

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.ip_forward /etc/sysctl.conf

The ability to forward packets is only appropriate for routers. If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.ip_forward" kernel parameter, run the following command: 

# sysctl -w net.ipv4.ip_forward=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.ip_forward = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000117

__Vuln ID__ V-38512

__Severity__ medium

__Group Title__ SRG-OS-000146

__Rule ID__ SV-50313r2_rule

__STIG ID__ RHEL-06-000117

__Rule Title__

`The operating system must prevent public IPv4 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.`

__Discussion__

```
The "iptables" service provides the system's host-based firewalling capability for IPv4 and ICMP.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the "iptables" service: 

# service iptables status

If the service is not running, it should return the following: 

iptables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "iptables" service can be enabled with the following commands: 

# chkconfig iptables on
# service iptables start
```

__CCI__

```
CCI-001100
The information system prevents public access into the organization's internal networks except as appropriately mediated by managed interfaces employing boundary protection devices.
NIST SP 800-53 :: SC-7 (2)
NIST SP 800-53A :: SC-7 (2).1 (ii)


```


### RHEL-06-000120

__Vuln ID__ V-38513

__Severity__ medium

__Group Title__ SRG-OS-000231

__Rule ID__ SV-50314r1_rule

__STIG ID__ RHEL-06-000120

__Rule Title__

`The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.`

__Discussion__

```
In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
```

__Check Content__

```
Inspect the file "/etc/sysconfig/iptables" to determine the default policy for the INPUT chain. It should be set to DROP. 

# grep ":INPUT" /etc/sysconfig/iptables

If the default policy for the INPUT chain is not set to DROP, this is a finding.
```

__Fix Text__

```
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in "/etc/sysconfig/iptables": 

:INPUT DROP [0:0]
```

__CCI__

```
CCI-000066
The organization enforces requirements for remote connections to the information system.
NIST SP 800-53 :: AC-17 e
NIST SP 800-53A :: AC-17.1 (v)


```


### RHEL-06-000124

__Vuln ID__ V-38514

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50315r4_rule

__STIG ID__ RHEL-06-000124

__Rule Title__

`The Datagram Congestion Control Protocol (DCCP) must be disabled unless required.`

__Discussion__

```
Disabling DCCP protects the system against exploitation of any flaws in its implementation.
```

__Check Content__

```
If the system is configured to prevent the loading of the "dccp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r dccp /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.
```

__Fix Text__

```
The Datagram Congestion Control Protocol (DCCP) is a relatively new transport layer protocol, designed to support streaming media and telephony. To configure the system to prevent the "dccp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install dccp /bin/true
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000125

__Vuln ID__ V-38515

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50316r4_rule

__STIG ID__ RHEL-06-000125

__Rule Title__

`The Stream Control Transmission Protocol (SCTP) must be disabled unless required.`

__Discussion__

```
Disabling SCTP protects the system against exploitation of any flaws in its implementation.
```

__Check Content__

```
If the system is configured to prevent the loading of the "sctp" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r sctp /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.
```

__Fix Text__

```
The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the "sctp" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install sctp /bin/true
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000126

__Vuln ID__ V-38516

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50317r3_rule

__STIG ID__ RHEL-06-000126

__Rule Title__

`The Reliable Datagram Sockets (RDS) protocol must be disabled unless required.`

__Discussion__

```
Disabling RDS protects the system against exploitation of any flaws in its implementation.
```

__Check Content__

```
If the system is configured to prevent the loading of the "rds" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated "/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r rds /etc/modprobe.conf /etc/modprobe.d

If no line is returned, this is a finding.
```

__Fix Text__

```
The Reliable Datagram Sockets (RDS) protocol is a transport layer protocol designed to provide reliable high-bandwidth, low-latency communications between nodes in a cluster. To configure the system to prevent the "rds" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install rds /bin/true
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000127

__Vuln ID__ V-38517

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50318r4_rule

__STIG ID__ RHEL-06-000127

__Rule Title__

`The Transparent Inter-Process Communication (TIPC) protocol must be disabled unless required.`

__Discussion__

```
Disabling TIPC protects the system against exploitation of any flaws in its implementation.
```

__Check Content__

```
If the system is configured to prevent the loading of the "tipc" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r tipc /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.
```

__Fix Text__

```
The Transparent Inter-Process Communication (TIPC) protocol is designed to provide communications between nodes in a cluster. To configure the system to prevent the "tipc" kernel module from being loaded, add the following line to a file in the directory "/etc/modprobe.d": 

install tipc /bin/true
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000133

__Vuln ID__ V-38518

__Severity__ medium

__Group Title__ SRG-OS-000206

__Rule ID__ SV-50319r2_rule

__STIG ID__ RHEL-06-000133

__Rule Title__

`All rsyslog-generated log files must be owned by root.`

__Discussion__

```
The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access.
```

__Check Content__

```
The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". To see the owner of a given log file, run the following command:

$ ls -l [LOGFILE]

Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration. 

If the owner is not root, this is a finding. 
```

__Fix Text__

```
The owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's owner:

$ ls -l [LOGFILE]

If the owner is not "root", run the following command to correct this:

# chown root [LOGFILE]
```

__CCI__

```
CCI-001314
The information system reveals error messages only to organization-defined personnel or roles.
NIST SP 800-53 :: SI-11 c
NIST SP 800-53A :: SI-11.1 (iv)
NIST SP 800-53 Revision 4 :: SI-11 b


```


### RHEL-06-000134

__Vuln ID__ V-38519

__Severity__ medium

__Group Title__ SRG-OS-000206

__Rule ID__ SV-50320r2_rule

__STIG ID__ RHEL-06-000134

__Rule Title__

`All rsyslog-generated log files must be group-owned by root.`

__Discussion__

```
The log files generated by rsyslog contain valuable information regarding system configuration, user authentication, and other such information. Log files should be protected from unauthorized access.
```

__Check Content__

```
The group-owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". To see the group-owner of a given log file, run the following command:

$ ls -l [LOGFILE]

Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.

If the group-owner is not root, this is a finding.
```

__Fix Text__

```
The group-owner of all log files written by "rsyslog" should be root. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's group owner:

$ ls -l [LOGFILE]

If the owner is not "root", run the following command to correct this:

# chgrp root [LOGFILE]
```

__CCI__

```
CCI-001314
The information system reveals error messages only to organization-defined personnel or roles.
NIST SP 800-53 :: SI-11 c
NIST SP 800-53A :: SI-11.1 (iv)
NIST SP 800-53 Revision 4 :: SI-11 b


```


### RHEL-06-000136

__Vuln ID__ V-38520

__Severity__ medium

__Group Title__ SRG-OS-000215

__Rule ID__ SV-50321r1_rule

__STIG ID__ RHEL-06-000136

__Rule Title__

`The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.`

__Discussion__

```
A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.
```

__Check Content__

```
To ensure logs are sent to a remote host, examine the file "/etc/rsyslog.conf". If using UDP, a line similar to the following should be present: 

*.* @[loghost.example.com]

If using TCP, a line similar to the following should be present: 

*.* @@[loghost.example.com]

If using RELP, a line similar to the following should be present: 

*.* :omrelp:[loghost.example.com]


If none of these are present, this is a finding.
```

__Fix Text__

```
To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments. 
To use UDP for log message delivery: 

*.* @[loghost.example.com]


To use TCP for log message delivery: 

*.* @@[loghost.example.com]


To use RELP for log message delivery: 

*.* :omrelp:[loghost.example.com]
```

__CCI__

```
CCI-001348
The information system backs up audit records on an organization-defined frequency onto a different system or system component than the system or component being audited.
NIST SP 800-53 :: AU-9 (2)
NIST SP 800-53A :: AU-9 (2).1 (iii)
NIST SP 800-53 Revision 4 :: AU-9 (2)


```


### RHEL-06-000137

__Vuln ID__ V-38521

__Severity__ medium

__Group Title__ SRG-OS-000043

__Rule ID__ SV-50322r1_rule

__STIG ID__ RHEL-06-000137

__Rule Title__

`The operating system must support the requirement to centrally manage the content of audit records generated by organization defined information system components.`

__Discussion__

```
A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.
```

__Check Content__

```
To ensure logs are sent to a remote host, examine the file "/etc/rsyslog.conf". If using UDP, a line similar to the following should be present: 

*.* @[loghost.example.com]

If using TCP, a line similar to the following should be present: 

*.* @@[loghost.example.com]

If using RELP, a line similar to the following should be present: 

*.* :omrelp:[loghost.example.com]


If none of these are present, this is a finding.
```

__Fix Text__

```
To configure rsyslog to send logs to a remote log server, open "/etc/rsyslog.conf" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting "[loghost.example.com]" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments. 
To use UDP for log message delivery: 

*.* @[loghost.example.com]


To use TCP for log message delivery: 

*.* @@[loghost.example.com]


To use RELP for log message delivery: 

*.* :omrelp:[loghost.example.com]
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000167

__Vuln ID__ V-38522

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50323r3_rule

__STIG ID__ RHEL-06-000167

__Rule Title__

`The audit system must be configured to audit all attempts to alter system time through settimeofday.`

__Discussion__

```
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "settimeofday" system call, run the following command:

$ sudo grep -w "settimeofday" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding. 
```

__Fix Text__

```
On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S settimeofday -k audit_time_rules

On a 64-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b64 -S settimeofday -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000083

__Vuln ID__ V-38523

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50324r2_rule

__STIG ID__ RHEL-06-000083

__Rule Title__

`The system must not accept IPv4 source-routed packets on any interface.`

__Discussion__

```
Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.accept_source_route" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_source_route

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.accept_source_route /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.accept_source_route" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.accept_source_route=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.accept_source_route = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000084

__Vuln ID__ V-38524

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50325r2_rule

__STIG ID__ RHEL-06-000084

__Rule Title__

`The system must not accept ICMPv4 redirect packets on any interface.`

__Discussion__

```
Accepting ICMP redirects has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.accept_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.accept_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000169

__Vuln ID__ V-38525

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50326r4_rule

__STIG ID__ RHEL-06-000169

__Rule Title__

`The audit system must be configured to audit all attempts to alter system time through stime.`

__Discussion__

```
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
```

__Check Content__

```
If the system is 64-bit only, this is not applicable.

To determine if the system is configured to audit calls to the "stime" system call, run the following command:

$ sudo grep -w "stime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding. 
```

__Fix Text__

```
On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S stime -k audit_time_rules

On a 64-bit system, the "-S stime" is not necessary. The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000086

__Vuln ID__ V-38526

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50327r2_rule

__STIG ID__ RHEL-06-000086

__Rule Title__

`The system must not accept ICMPv4 secure redirect packets on any interface.`

__Discussion__

```
Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.secure_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.secure_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.secure_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding.
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.secure_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.secure_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.secure_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000171

__Vuln ID__ V-38527

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50328r3_rule

__STIG ID__ RHEL-06-000171

__Rule Title__

`The audit system must be configured to audit all attempts to alter system time through clock_settime.`

__Discussion__

```
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "clock_settime" system call, run the following command:

$ sudo grep -w "clock_settime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding. 
```

__Fix Text__

```
On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S clock_settime -k audit_time_rules

On a 64-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b64 -S clock_settime -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000088

__Vuln ID__ V-38528

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50329r2_rule

__STIG ID__ RHEL-06-000088

__Rule Title__

`The system must log Martian packets.`

__Discussion__

```
The presence of "martian" packets (which have impossible addresses) as well as spoofed packets, source-routed packets, and redirects could be a sign of nefarious network activity. Logging these packets enables this activity to be detected.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.log_martians" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.log_martians

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.log_martians /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.log_martians" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.log_martians=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.log_martians = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000089

__Vuln ID__ V-38529

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50330r2_rule

__STIG ID__ RHEL-06-000089

__Rule Title__

`The system must not accept IPv4 source-routed packets by default.`

__Discussion__

```
Accepting source-routed packets in the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.default.accept_source_route" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.accept_source_route

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.accept_source_route /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.default.accept_source_route" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.accept_source_route=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.accept_source_route = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000173

__Vuln ID__ V-38530

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50331r2_rule

__STIG ID__ RHEL-06-000173

__Rule Title__

`The audit system must be configured to audit all attempts to alter system time through /etc/localtime.`

__Discussion__

```
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
```

__Check Content__

```
To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command: 

$ sudo grep -w "/etc/localtime" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules": 

-w /etc/localtime -p wa -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000174

__Vuln ID__ V-38531

__Severity__ low

__Group Title__ SRG-OS-000004

__Rule ID__ SV-50332r2_rule

__STIG ID__ RHEL-06-000174

__Rule Title__

`The operating system must automatically audit account creation.`

__Discussion__

```
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
```

__Check Content__

```
To determine if the system is configured to audit account changes, run the following command: 

$ sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules

If the system is configured to watch for account changes, lines should be returned for each file specified (and with "-p wa" for each). 

If the system is not configured to audit account changes, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 

# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes
```

__CCI__

```
CCI-000018
The information system automatically audits account creation actions.
NIST SP 800-53 :: AC-2 (4)
NIST SP 800-53A :: AC-2 (4).1 (i&ii)
NIST SP 800-53 Revision 4 :: AC-2 (4)


```


### RHEL-06-000090

__Vuln ID__ V-38532

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50333r2_rule

__STIG ID__ RHEL-06-000090

__Rule Title__

`The system must not accept ICMPv4 secure redirect packets by default.`

__Discussion__

```
Accepting "secure" ICMP redirects (from those gateways listed as default gateways) has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.default.secure_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.secure_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.secure_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.default.secure_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.secure_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.secure_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000091

__Vuln ID__ V-38533

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50334r3_rule

__STIG ID__ RHEL-06-000091

__Rule Title__

`The system must ignore ICMPv4 redirect messages by default.`

__Discussion__

```
This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.
```

__Check Content__

```
The status of the "net.ipv4.conf.default.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.default.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.accept_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000175

__Vuln ID__ V-38534

__Severity__ low

__Group Title__ SRG-OS-000239

__Rule ID__ SV-50335r2_rule

__STIG ID__ RHEL-06-000175

__Rule Title__

`The operating system must automatically audit account modification.`

__Discussion__

```
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
```

__Check Content__

```
To determine if the system is configured to audit account changes, run the following command: 

$sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules

If the system is configured to watch for account changes, lines should be returned for each file specified (and with "-p wa" for each). 

If the system is not configured to audit account changes, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 

# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes
```

__CCI__

```
CCI-001403
The information system automatically audits account modification actions.
NIST SP 800-53 :: AC-2 (4)
NIST SP 800-53A :: AC-2 (4).1 (i&ii)
NIST SP 800-53 Revision 4 :: AC-2 (4)


```


### RHEL-06-000092

__Vuln ID__ V-38535

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50336r2_rule

__STIG ID__ RHEL-06-000092

__Rule Title__

`The system must not respond to ICMPv4 sent to a broadcast address.`

__Discussion__

```
Ignoring ICMP echo requests (pings) sent to broadcast or multicast addresses makes the system slightly more difficult to enumerate on the network.
```

__Check Content__

```
The status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_echo_ignore_broadcasts

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.icmp_echo_ignore_broadcasts /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.icmp_echo_ignore_broadcasts" kernel parameter, run the following command: 

# sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.icmp_echo_ignore_broadcasts = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000176

__Vuln ID__ V-38536

__Severity__ low

__Group Title__ SRG-OS-000240

__Rule ID__ SV-50337r2_rule

__STIG ID__ RHEL-06-000176

__Rule Title__

`The operating system must automatically audit account disabling actions.`

__Discussion__

```
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
```

__Check Content__

```
To determine if the system is configured to audit account changes, run the following command: 

$sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules

If the system is configured to watch for account changes, lines should be returned for each file specified (and with "-p wa" for each). 

If the system is not configured to audit account changes, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 

# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes
```

__CCI__

```
CCI-001404
The information system automatically audits account disabling actions.
NIST SP 800-53 :: AC-2 (4)
NIST SP 800-53A :: AC-2 (4).1 (i&ii)
NIST SP 800-53 Revision 4 :: AC-2 (4)


```


### RHEL-06-000093

__Vuln ID__ V-38537

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50338r2_rule

__STIG ID__ RHEL-06-000093

__Rule Title__

`The system must ignore ICMPv4 bogus error responses.`

__Discussion__

```
Ignoring bogus ICMP error responses reduces log size, although some activity would not be logged.
```

__Check Content__

```
The status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.icmp_ignore_bogus_error_responses

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.icmp_ignore_bogus_error_responses /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.icmp_ignore_bogus_error_responses" kernel parameter, run the following command: 

# sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.icmp_ignore_bogus_error_responses = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000177

__Vuln ID__ V-38538

__Severity__ low

__Group Title__ SRG-OS-000241

__Rule ID__ SV-50339r2_rule

__STIG ID__ RHEL-06-000177

__Rule Title__

`The operating system must automatically audit account termination.`

__Discussion__

```
In addition to auditing new user and group accounts, these watches will alert the system administrator(s) to any modifications. Any unexpected users, groups, or modifications should be investigated for legitimacy.
```

__Check Content__

```
To determine if the system is configured to audit account changes, run the following command: 

$sudo egrep -w '(/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/security/opasswd)' /etc/audit/audit.rules

If the system is configured to watch for account changes, lines should be returned for each file specified (and with "-p wa" for each). 

If the system is not configured to audit account changes, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules", in order to capture events that modify account changes: 

# audit_account_changes
-w /etc/group -p wa -k audit_account_changes
-w /etc/passwd -p wa -k audit_account_changes
-w /etc/gshadow -p wa -k audit_account_changes
-w /etc/shadow -p wa -k audit_account_changes
-w /etc/security/opasswd -p wa -k audit_account_changes
```

__CCI__

```
CCI-001405
The information system automatically audits account removal actions.
NIST SP 800-53 :: AC-2 (4)
NIST SP 800-53A :: AC-2 (4).1 (i&ii)
NIST SP 800-53 Revision 4 :: AC-2 (4)


```


### RHEL-06-000095

__Vuln ID__ V-38539

__Severity__ medium

__Group Title__ SRG-OS-000142

__Rule ID__ SV-50340r2_rule

__STIG ID__ RHEL-06-000095

__Rule Title__

`The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.`

__Discussion__

```
A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests.
```

__Check Content__

```
The status of the "net.ipv4.tcp_syncookies" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.tcp_syncookies

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.tcp_syncookies" kernel parameter, run the following command: 

# sysctl -w net.ipv4.tcp_syncookies=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.tcp_syncookies = 1
```

__CCI__

```
CCI-001095
The information system manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial of service attacks.
NIST SP 800-53 :: SC-5 (2)
NIST SP 800-53A :: SC-5 (2).1
NIST SP 800-53 Revision 4 :: SC-5 (2)


```


### RHEL-06-000182

__Vuln ID__ V-38540

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50341r4_rule

__STIG ID__ RHEL-06-000182

__Rule Title__

`The audit system must be configured to audit modifications to the systems network configuration.`

__Discussion__

```
The network environment should not be modified by anything other than administrator action. Any change to network parameters should be audited.
```

__Check Content__

```
If you are running x86_64 architecture, determine the values for sethostname:
$ uname -m; ausyscall i386 sethostname; ausyscall x86_64 sethostname
    
If the values returned are not identical verify that the system is configured to monitor network configuration changes for the i386 and x86_64 architectures:

$ sudo egrep -w '(sethostname|setdomainname|/etc/issue|/etc/issue.net|/etc/hosts|/etc/sysconfig/network)' /etc/audit/audit.rules

-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications

If the system is configured to watch for network configuration changes, a line should be returned for each file specified for both (and "-p wa" should be indicated for each).

If the system is not configured to audit changes of the network configuration, this is a finding.

```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

# audit_network_modifications
-a always,exit -F arch=ARCH -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000183

__Vuln ID__ V-38541

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50342r2_rule

__STIG ID__ RHEL-06-000183

__Rule Title__

`The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).`

__Discussion__

```
The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited.
```

__Check Content__

```
To determine if the system is configured to audit changes to its SELinux configuration files, run the following command: 

$ sudo grep -w "/etc/selinux" /etc/audit/audit.rules

If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including "-p wa" indicating permissions that are watched). 

If the system is not configured to audit attempts to change the MAC policy, this is a finding.
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules": 

-w /etc/selinux/ -p wa -k MAC-policy
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000096

__Vuln ID__ V-38542

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50343r2_rule

__STIG ID__ RHEL-06-000096

__Rule Title__

`The system must use a reverse-path filter for IPv4 network traffic when possible on all interfaces.`

__Discussion__

```
Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.rp_filter" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.rp_filter

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.rp_filter /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.rp_filter" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.rp_filter=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.rp_filter = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000184

__Vuln ID__ V-38543

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50344r3_rule

__STIG ID__ RHEL-06-000184

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using chmod.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "chmod" system call, run the following command:

$ sudo grep -w "chmod" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If the system is not configured to audit permission changes, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S chmod -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S chmod -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S chmod -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S chmod -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000097

__Vuln ID__ V-38544

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50345r2_rule

__STIG ID__ RHEL-06-000097

__Rule Title__

`The system must use a reverse-path filter for IPv4 network traffic when possible by default.`

__Discussion__

```
Enabling reverse path filtering drops packets with source addresses that should not have been able to be received on the interface they were received on. It should not be used on systems which are routers for complicated networks, but is helpful for end hosts and routers serving small networks.
```

__Check Content__

```
The status of the "net.ipv4.conf.default.rp_filter" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.rp_filter

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.rp_filter /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.default.rp_filter" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.rp_filter=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.rp_filter = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000185

__Vuln ID__ V-38545

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50346r3_rule

__STIG ID__ RHEL-06-000185

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using chown.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "chown" system call, run the following command:

$ sudo grep -w "chown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines.

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S chown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S chown -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S chown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S chown -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000186

__Vuln ID__ V-38547

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50348r3_rule

__STIG ID__ RHEL-06-000186

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fchmod.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fchmod" system call, run the following command:

$ sudo grep -w "fchmod" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchmod -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fchmod -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchmod -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fchmod -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000099

__Vuln ID__ V-38548

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50349r3_rule

__STIG ID__ RHEL-06-000099

__Rule Title__

`The system must ignore ICMPv6 redirects by default.`

__Discussion__

```
An illicit ICMP redirect message could result in a man-in-the-middle attack.
```

__Check Content__

```
If IPv6 is disabled, this is not applicable.

The status of the "net.ipv6.conf.default.accept_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv6.conf.default.accept_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv6.conf.default.accept_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv6.conf.default.accept_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv6.conf.default.accept_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv6.conf.default.accept_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000103

__Vuln ID__ V-38549

__Severity__ medium

__Group Title__ SRG-OS-000152

__Rule ID__ SV-50350r3_rule

__STIG ID__ RHEL-06-000103

__Rule Title__

`The system must employ a local IPv6 firewall.`

__Discussion__

```
The "ip6tables" service provides the system's host-based firewalling capability for IPv6 and ICMPv6.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service: 

# service ip6tables status

If the service is not running, it should return the following: 

ip6tables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "ip6tables" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start
```

__CCI__

```
CCI-001118
The information system implements host-based boundary protection mechanisms for servers, workstations, and mobile devices.
NIST SP 800-53 :: SC-7 (12)
NIST SP 800-53A :: SC-7 (12).1


```


### RHEL-06-000187

__Vuln ID__ V-38550

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50351r3_rule

__STIG ID__ RHEL-06-000187

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fchmodat.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fchmodat" system call, run the following command:

$ sudo grep -w "fchmodat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchmodat -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fchmodat -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchmodat -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fchmodat -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000106

__Vuln ID__ V-38551

__Severity__ medium

__Group Title__ SRG-OS-000145

__Rule ID__ SV-50352r3_rule

__STIG ID__ RHEL-06-000106

__Rule Title__

`The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.`

__Discussion__

```
The "ip6tables" service provides the system's host-based firewalling capability for IPv6 and ICMPv6.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

If IPV6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service: 

# service ip6tables status

If the service is not running, it should return the following: 

ip6tables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "ip6tables" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start
```

__CCI__

```
CCI-001098
The information system connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.
NIST SP 800-53 :: SC-7 b
NIST SP 800-53A :: SC-7.1 (iv)
NIST SP 800-53 Revision 4 :: SC-7 c


```


### RHEL-06-000188

__Vuln ID__ V-38552

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50353r3_rule

__STIG ID__ RHEL-06-000188

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fchown.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fchown" system call, run the following command:

$ sudo grep -w "fchown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fchown -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fchown -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000107

__Vuln ID__ V-38553

__Severity__ medium

__Group Title__ SRG-OS-000146

__Rule ID__ SV-50354r3_rule

__STIG ID__ RHEL-06-000107

__Rule Title__

`The operating system must prevent public IPv6 access into an organizations internal networks, except as appropriately mediated by managed interfaces employing boundary protection devices.`

__Discussion__

```
The "ip6tables" service provides the system's host-based firewalling capability for IPv6 and ICMPv6.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

If IPv6 is disabled, this is not applicable.

Run the following command to determine the current status of the "ip6tables" service: 

# service ip6tables status

If the service is not running, it should return the following: 

ip6tables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "ip6tables" service can be enabled with the following commands: 

# chkconfig ip6tables on
# service ip6tables start
```

__CCI__

```
CCI-001100
The information system prevents public access into the organization's internal networks except as appropriately mediated by managed interfaces employing boundary protection devices.
NIST SP 800-53 :: SC-7 (2)
NIST SP 800-53A :: SC-7 (2).1 (ii)


```


### RHEL-06-000189

__Vuln ID__ V-38554

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50355r3_rule

__STIG ID__ RHEL-06-000189

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fchownat.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fchownat" system call, run the following command:

$ sudo grep -w "fchownat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fchownat -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fchownat -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fchownat -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fchownat -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000113

__Vuln ID__ V-38555

__Severity__ medium

__Group Title__ SRG-OS-000152

__Rule ID__ SV-50356r2_rule

__STIG ID__ RHEL-06-000113

__Rule Title__

`The system must employ a local IPv4 firewall.`

__Discussion__

```
The "iptables" service provides the system's host-based firewalling capability for IPv4 and ICMP.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the "iptables" service: 

# service iptables status

If the service is not running, it should return the following: 

iptables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "iptables" service can be enabled with the following commands: 

# chkconfig iptables on
# service iptables start
```

__CCI__

```
CCI-001118
The information system implements host-based boundary protection mechanisms for servers, workstations, and mobile devices.
NIST SP 800-53 :: SC-7 (12)
NIST SP 800-53A :: SC-7 (12).1


```


### RHEL-06-000190

__Vuln ID__ V-38556

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50357r3_rule

__STIG ID__ RHEL-06-000190

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fremovexattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fremovexattr" system call, run the following command:

$ sudo grep -w "fremovexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fremovexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fremovexattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fremovexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fremovexattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000191

__Vuln ID__ V-38557

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50358r3_rule

__STIG ID__ RHEL-06-000191

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using fsetxattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "fsetxattr" system call, run the following command:

$ sudo grep -w "fsetxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S fsetxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S fsetxattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S fsetxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S fsetxattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000192

__Vuln ID__ V-38558

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50359r3_rule

__STIG ID__ RHEL-06-000192

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using lchown.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "lchown" system call, run the following command:

$ sudo grep -w "lchown" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S lchown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S lchown -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S lchown -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S lchown -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000193

__Vuln ID__ V-38559

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50360r3_rule

__STIG ID__ RHEL-06-000193

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using lremovexattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "lremovexattr" system call, run the following command:

$ sudo grep -w "lremovexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S lremovexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S lremovexattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S lremovexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S lremovexattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000116

__Vuln ID__ V-38560

__Severity__ medium

__Group Title__ SRG-OS-000145

__Rule ID__ SV-50361r2_rule

__STIG ID__ RHEL-06-000116

__Rule Title__

`The operating system must connect to external networks or information systems only through managed IPv4 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.`

__Discussion__

```
The "iptables" service provides the system's host-based firewalling capability for IPv4 and ICMP.
```

__Check Content__

```
If the system is a cross-domain system, this is not applicable.

Run the following command to determine the current status of the "iptables" service: 

# service iptables status

If the service is not running, it should return the following: 

iptables: Firewall is not running.


If the service is not running, this is a finding.
```

__Fix Text__

```
The "iptables" service can be enabled with the following commands: 

# chkconfig iptables on
# service iptables start
```

__CCI__

```
CCI-001098
The information system connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.
NIST SP 800-53 :: SC-7 b
NIST SP 800-53A :: SC-7.1 (iv)
NIST SP 800-53 Revision 4 :: SC-7 c


```


### RHEL-06-000194

__Vuln ID__ V-38561

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50362r3_rule

__STIG ID__ RHEL-06-000194

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using lsetxattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "lsetxattr" system call, run the following command:

$ sudo grep -w "lsetxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S lsetxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S lsetxattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S lsetxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S lsetxattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000195

__Vuln ID__ V-38563

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50364r3_rule

__STIG ID__ RHEL-06-000195

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using removexattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "removexattr" system call, run the following command:

$ sudo grep -w "removexattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding.
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S removexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S removexattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S removexattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S removexattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000196

__Vuln ID__ V-38565

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50366r3_rule

__STIG ID__ RHEL-06-000196

__Rule Title__

`The audit system must be configured to audit all discretionary access control permission modifications using setxattr.`

__Discussion__

```
The changing of file permissions could indicate that a user is attempting to gain access to information that would otherwise be disallowed. Auditing DAC modifications can facilitate the identification of patterns of abuse among both authorized and unauthorized users.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "setxattr" system call, run the following command:

$ sudo grep -w "setxattr" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file permission changes for all users and root. Add the following to "/etc/audit/audit.rules": 

-a always,exit -F arch=b32 -S setxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b32 -S setxattr -F auid=0 -k perm_mod

If the system is 64-bit, then also add the following: 

-a always,exit -F arch=b64 -S setxattr -F auid>=500 -F auid!=4294967295 \
-k perm_mod
-a always,exit -F arch=b64 -S setxattr -F auid=0 -k perm_mod
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000197

__Vuln ID__ V-38566

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50367r2_rule

__STIG ID__ RHEL-06-000197

__Rule Title__

`The audit system must be configured to audit failed attempts to access files and programs.`

__Discussion__

```
Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.
```

__Check Content__

```
To verify that the audit system collects unauthorized file accesses, run the following commands: 

# grep EACCES /etc/audit/audit.rules



# grep EPERM /etc/audit/audit.rules


If either command lacks output, this is a finding.
```

__Fix Text__

```
At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EACCES -F auid=0 -k access
-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \
-S ftruncate -F exit=-EPERM -F auid=0 -k access
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000198

__Vuln ID__ V-38567

__Severity__ low

__Group Title__ SRG-OS-000020

__Rule ID__ SV-50368r4_rule

__STIG ID__ RHEL-06-000198

__Rule Title__

`The audit system must be configured to audit all use of setuid and setgid programs.`

__Discussion__

```
Privileged programs are subject to escalation-of-privilege attacks, which attempt to subvert their normal role of providing some necessary but limited capability. As such, motivation exists to monitor these programs for unusual activity.
```

__Check Content__

```
To verify that auditing of privileged command use is configured, run the following command once for each local partition [PART] to find relevant setuid / setgid programs:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Run the following command to verify entries in the audit rules for all programs found with the previous command:

$ sudo grep path /etc/audit/audit.rules

It should be the case that all relevant setuid / setgid programs have a line in the audit rules. If that is not the case, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect the execution of privileged commands for all users and root. To find the relevant setuid / setgid programs, run the following command for each local partition [PART]:

$ sudo find [PART] -xdev -type f -perm /6000 2>/dev/null

Then, for each setuid / setgid program on the system, add a line of the following form to "/etc/audit/audit.rules", where [SETUID_PROG_PATH] is the full path to each setuid / setgid program in the list:

-a always,exit -F path=[SETUID_PROG_PATH] -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged
```

__CCI__

```
CCI-000040
The organization audits any use of privileged accounts, or roles, with access to organization defined security functions or security-relevant information, when accessing other system functions.
NIST SP 800-53 :: AC-6 (2)
NIST SP 800-53A :: AC-6 (2).1 (iii)


```


### RHEL-06-000199

__Vuln ID__ V-38568

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50369r3_rule

__STIG ID__ RHEL-06-000199

__Rule Title__

`The audit system must be configured to audit successful file system mounts.`

__Discussion__

```
The unauthorized exportation of data to external media could result in an information leak where classified information, Privacy Act information, and intellectual property could be lost. An audit trail should be created each time a filesystem is mounted to help identify and guard against information loss.
```

__Check Content__

```
To verify that auditing is configured for all media exportation events, run the following command: 

$ sudo grep -w "mount" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return several lines. 

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect media exportation events for all users and root. Add the following to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

-a always,exit -F arch=ARCH -S mount -F auid>=500 -F auid!=4294967295 -k export
-a always,exit -F arch=ARCH -S mount -F auid=0 -k export
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000057

__Vuln ID__ V-38569

__Severity__ low

__Group Title__ SRG-OS-000069

__Rule ID__ SV-50370r1_rule

__STIG ID__ RHEL-06-000057

__Rule Title__

`The system must require passwords to contain at least one uppercase alphabetic character.`

__Discussion__

```
Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.
```

__Check Content__

```
To check how many uppercase characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "ucredit" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as "ucredit=-1". 
If ucredit is not found or not set to the required value, this is a finding.
```

__Fix Text__

```
The pam_cracklib module's "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. Add "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.
```

__CCI__

```
CCI-000192
The information system enforces password complexity by the minimum number of upper case characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)


```


### RHEL-06-000058

__Vuln ID__ V-38570

__Severity__ low

__Group Title__ SRG-OS-000266

__Rule ID__ SV-50371r1_rule

__STIG ID__ RHEL-06-000058

__Rule Title__

`The system must require passwords to contain at least one special character.`

__Discussion__

```
Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.
```

__Check Content__

```
To check how many special characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "ocredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one special character in a password. This would appear as "ocredit=-1". 
If ocredit is not found or not set to the required value, this is a finding.
```

__Fix Text__

```
The pam_cracklib module's "ocredit=" parameter controls requirements for usage of special (or ``other'') characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character. Add "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.
```

__CCI__

```
CCI-001619
The information system enforces password complexity by the minimum number of special characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)


```


### RHEL-06-000059

__Vuln ID__ V-38571

__Severity__ low

__Group Title__ SRG-OS-000070

__Rule ID__ SV-50372r2_rule

__STIG ID__ RHEL-06-000059

__Rule Title__

`The system must require passwords to contain at least one lower-case alphabetic character.`

__Discussion__

```
Requiring a minimum number of lower-case characters makes password guessing attacks more difficult by ensuring a larger search space.
```

__Check Content__

```
To check how many lower-case characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "lcredit" parameter (as a negative number) will indicate how many lower-case characters are required. The DoD requires at least one lower-case character in a password. This would appear as "lcredit=-1". 

If lcredit is not found or not set to the required value, this is a finding.

```

__Fix Text__

```
The pam_cracklib module's "lcredit=" parameter controls requirements for usage of lower-case letters in a password. When set to a negative number, any password will be required to contain that many lower-case characters. Add "lcredit=-1" after pam_cracklib.so to require use of a lower-case character in passwords.
```

__CCI__

```
CCI-000193
The information system enforces password complexity by the minimum number of lower case characters used.
NIST SP 800-53 :: IA-5 (1) (a)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (a)


```


### RHEL-06-000060

__Vuln ID__ V-38572

__Severity__ low

__Group Title__ SRG-OS-000072

__Rule ID__ SV-50373r2_rule

__STIG ID__ RHEL-06-000060

__Rule Title__

`The system must require at least eight characters be changed between the old and new passwords during a password change.`

__Discussion__

```
Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however.
```

__Check Content__

```
To check how many characters must differ during a password change, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

The "difok" parameter will indicate how many characters must differ. The DoD requires eight characters differ during a password change. This would appear as "difok=8". 

If difok is not found or not set to the required value, this is a finding.
```

__Fix Text__

```
The pam_cracklib module's "difok" parameter controls requirements for usage of different characters during a password change. Add "difok=[NUM]" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 8.
```

__CCI__

```
CCI-000195
The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.
NIST SP 800-53 :: IA-5 (1) (b)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (b)


```


### RHEL-06-000061

__Vuln ID__ V-38573

__Severity__ medium

__Group Title__ SRG-OS-000021

__Rule ID__ SV-50374r4_rule

__STIG ID__ RHEL-06-000061

__Rule Title__

`The system must disable accounts after three consecutive unsuccessful logon attempts.`

__Discussion__

```
Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.
```

__Check Content__

```
To ensure the failed password attempt policy is configured correctly, run the following command: 

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

The output should show "deny=3" for both files. 
If that is not the case, this is a finding.
```

__Fix Text__

```
To configure the system to lock out accounts after a number of incorrect logon attempts using "pam_faillock.so", modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
```

__CCI__

```
CCI-000044
The information system enforces the organization-defined limit of consecutive invalid logon attempts by a user during the organization-defined time period.
NIST SP 800-53 :: AC-7 a
NIST SP 800-53A :: AC-7.1 (ii)
NIST SP 800-53 Revision 4 :: AC-7 a


```


### RHEL-06-000062

__Vuln ID__ V-38574

__Severity__ medium

__Group Title__ SRG-OS-000120

__Rule ID__ SV-50375r3_rule

__STIG ID__ RHEL-06-000062

__Rule Title__

`The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (system-auth).`

__Discussion__

```
Using a stronger hashing algorithm makes password cracking attacks more difficult.
```

__Check Content__

```
Inspect the "password" section of "/etc/pam.d/system-auth", "/etc/pam.d/system-auth-ac", and other files in "/etc/pam.d" to identify the number of occurrences where the "pam_unix.so" module is used in the "password" section.
$ grep -E -c 'password.*pam_unix.so' /etc/pam.d/*

/etc/pam.d/atd:0
/etc/pam.d/config-util:0
/etc/pam.d/crond:0
/etc/pam.d/login:0
/etc/pam.d/other:0
/etc/pam.d/passwd:0
/etc/pam.d/password-auth:1
/etc/pam.d/password-auth-ac:1
/etc/pam.d/sshd:0
/etc/pam.d/su:0
/etc/pam.d/sudo:0
/etc/pam.d/system-auth:1
/etc/pam.d/system-auth-ac:1
/etc/pam.d/vlock:0

Note: The number adjacent to the file name indicates how many occurrences of the "pam_unix.so" module are found in the password section.

If the "pam_unix.so" module is not defined in the "password" section of "/etc/pam.d/system-auth", "/etc/pam.d/system-auth-ac", "/etc/pam.d/password-auth", and "/etc/pam.d/password-auth-ac" at a minimum, this is a finding.

Verify that the "sha512" variable is used with each instance of the "pam_unix.so" module in the "password" section:

$ grep password /etc/pam.d/* | grep pam_unix.so | grep sha512

/etc/pam.d/password-auth:password    	sufficient    pam_unix.so sha512 [other arguments�]
/etc/pam.d/password-auth-ac:password    sufficient    pam_unix.so sha512 [other arguments�]
/etc/pam.d/system-auth:password    	sufficient    pam_unix.so sha512 [other arguments�]
/etc/pam.d/system-auth-ac:password    	sufficient    pam_unix.so sha512 [other arguments�]

If this list of files does not coincide with the previous command, this is a finding. 

If any of the identified "pam_unix.so" modules do not use the "sha512" variable, this is a finding.

```

__Fix Text__

```
In "/etc/pam.d/system-auth", "/etc/pam.d/system-auth-ac", "/etc/pam.d/password-auth", and "/etc/pam.d/password-auth-ac", among potentially other files, the "password" section of the files controls which PAM modules execute during a password change. Set the "pam_unix.so" module in the "password" section to include the argument "sha512", as shown below: 

password sufficient pam_unix.so sha512 [other arguments...]

This will help ensure when local users change their passwords, hashes for the new passwords will be generated using the SHA-512 algorithm. This is the default.

Note that any updates made to "/etc/pam.d/system-auth" will be overwritten by the "authconfig" program. The "authconfig" program should not be used.

```

__CCI__

```
CCI-000803
The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.
NIST SP 800-53 :: IA-7
NIST SP 800-53A :: IA-7.1
NIST SP 800-53 Revision 4 :: IA-7


```


### RHEL-06-000200

__Vuln ID__ V-38575

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50376r4_rule

__STIG ID__ RHEL-06-000200

__Rule Title__

`The audit system must be configured to audit user deletions of files and programs.`

__Discussion__

```
Auditing file deletions will create an audit trail for files that are removed from the system. The audit trail could aid in system troubleshooting, as well as detecting malicious processes that attempt to delete log files to conceal their presence.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "rmdir" system call, run the following command:

$ sudo grep -w "rmdir" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "unlink" system call, run the following command:

$ sudo grep -w "unlink" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "unlinkat" system call, run the following command:

$ sudo grep -w "unlinkat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "rename" system call, run the following command:

$ sudo grep -w "rename" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. To determine if the system is configured to audit calls to the "renameat" system call, run the following command:

$ sudo grep -w "renameat" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

If no line is returned, this is a finding. 
```

__Fix Text__

```
At a minimum, the audit system should collect file deletion events for all users and root. Add the following (or equivalent) to "/etc/audit/audit.rules", setting ARCH to either b32 or b64 as appropriate for your system: 

-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid=0 -k delete


```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000063

__Vuln ID__ V-38576

__Severity__ medium

__Group Title__ SRG-OS-000120

__Rule ID__ SV-50377r1_rule

__STIG ID__ RHEL-06-000063

__Rule Title__

`The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).`

__Discussion__

```
Using a stronger hashing algorithm makes password cracking attacks more difficult.
```

__Check Content__

```
Inspect "/etc/login.defs" and ensure the following line appears: 

ENCRYPT_METHOD SHA512


If it does not, this is a finding.
```

__Fix Text__

```
In "/etc/login.defs", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm: 

ENCRYPT_METHOD SHA512
```

__CCI__

```
CCI-000803
The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.
NIST SP 800-53 :: IA-7
NIST SP 800-53A :: IA-7.1
NIST SP 800-53 Revision 4 :: IA-7


```


### RHEL-06-000064

__Vuln ID__ V-38577

__Severity__ medium

__Group Title__ SRG-OS-000120

__Rule ID__ SV-50378r1_rule

__STIG ID__ RHEL-06-000064

__Rule Title__

`The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).`

__Discussion__

```
Using a stronger hashing algorithm makes password cracking attacks more difficult.
```

__Check Content__

```
Inspect "/etc/libuser.conf" and ensure the following line appears in the "[default]" section: 

crypt_style = sha512


If it does not, this is a finding.
```

__Fix Text__

```
In "/etc/libuser.conf", add or correct the following line in its "[defaults]" section to ensure the system will use the SHA-512 algorithm for password hashing: 

crypt_style = sha512
```

__CCI__

```
CCI-000803
The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.
NIST SP 800-53 :: IA-7
NIST SP 800-53A :: IA-7.1
NIST SP 800-53 Revision 4 :: IA-7


```


### RHEL-06-000201

__Vuln ID__ V-38578

__Severity__ low

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50379r2_rule

__STIG ID__ RHEL-06-000201

__Rule Title__

`The audit system must be configured to audit changes to the /etc/sudoers file.`

__Discussion__

```
The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.
```

__Check Content__

```
To verify that auditing is configured for system administrator actions, run the following command: 

$ sudo grep -w "/etc/sudoers" /etc/audit/audit.rules

If the system is configured to watch for changes to its sudoers configuration, a line should be returned (including "-p wa" indicating permissions that are watched). 

If there is no output, this is a finding.
```

__Fix Text__

```
At a minimum, the audit system should collect administrator actions for all users and root. Add the following to "/etc/audit/audit.rules": 

-w /etc/sudoers -p wa -k actions
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000065

__Vuln ID__ V-38579

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50380r2_rule

__STIG ID__ RHEL-06-000065

__Rule Title__

`The system boot loader configuration file(s) must be owned by root.`

__Discussion__

```
Only root should be able to modify important boot parameters.
```

__Check Content__

```
To check the ownership of "/boot/grub/grub.conf", run the command: 

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate that the owner is "root".
If it does not, this is a finding.
```

__Fix Text__

```
The file "/boot/grub/grub.conf" should be owned by the "root" user to prevent destruction or modification of the file. To properly set the owner of "/boot/grub/grub.conf", run the command: 

# chown root /boot/grub/grub.conf
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000202

__Vuln ID__ V-38580

__Severity__ medium

__Group Title__ SRG-OS-000064

__Rule ID__ SV-50381r2_rule

__STIG ID__ RHEL-06-000202

__Rule Title__

`The audit system must be configured to audit the loading and unloading of dynamic kernel modules.`

__Discussion__

```
The addition/removal of kernel modules can be used to alter the behavior of the kernel and potentially introduce malicious code into kernel space. It is important to have an audit trail of modules that have been introduced into the kernel.
```

__Check Content__

```
To determine if the system is configured to audit execution of module management programs, run the following commands:

$ sudo egrep -e "(-w |-F path=)/sbin/insmod" /etc/audit/audit.rules
$ sudo egrep -e "(-w |-F path=)/sbin/rmmod" /etc/audit/audit.rules
$ sudo egrep -e "(-w |-F path=)/sbin/modprobe" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line.

To determine if the system is configured to audit calls to the "init_module" system call, run the following command:

$ sudo grep -w "init_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

To determine if the system is configured to audit calls to the "delete_module" system call, run the following command:

$ sudo grep -w "delete_module" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If no line is returned for any of these commands, this is a finding. 
```

__Fix Text__

```
Add the following to "/etc/audit/audit.rules" in order to capture kernel module loading and unloading events, setting ARCH to either b32 or b64 as appropriate for your system: 

-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=[ARCH] -S init_module -S delete_module -k modules
```

__CCI__

```
CCI-000172
The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.
NIST SP 800-53 :: AU-12 c
NIST SP 800-53A :: AU-12.1 (iv)
NIST SP 800-53 Revision 4 :: AU-12 c


```


### RHEL-06-000066

__Vuln ID__ V-38581

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50382r2_rule

__STIG ID__ RHEL-06-000066

__Rule Title__

`The system boot loader configuration file(s) must be group-owned by root.`

__Discussion__

```
The "root" group is a highly-privileged group. Furthermore, the group-owner of this file should not have any access privileges anyway.
```

__Check Content__

```
To check the group ownership of "/boot/grub/grub.conf", run the command: 

$ ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate the group-owner is "root".
If it does not, this is a finding.
```

__Fix Text__

```
The file "/boot/grub/grub.conf" should be group-owned by the "root" group to prevent destruction or modification of the file. To properly set the group owner of "/boot/grub/grub.conf", run the command: 

# chgrp root /boot/grub/grub.conf
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000203

__Vuln ID__ V-38582

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50383r2_rule

__STIG ID__ RHEL-06-000203

__Rule Title__

`The xinetd service must be disabled if no network services utilizing it are enabled.`

__Discussion__

```
The xinetd service provides a dedicated listener service for some programs, which is no longer necessary for commonly-used network services. Disabling it ensures that these uncommon services are not running, and also prevents attacks against xinetd itself.
```

__Check Content__

```
If network services are using the xinetd service, this is not applicable.

To check that the "xinetd" service is disabled in system boot configuration, run the following command: 

# chkconfig "xinetd" --list

Output should indicate the "xinetd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "xinetd" --list
"xinetd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "xinetd" is disabled through current runtime configuration: 

# service xinetd status

If the service is disabled the command will return the following output: 

xinetd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "xinetd" service can be disabled with the following commands: 

# chkconfig xinetd off
# service xinetd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000067

__Vuln ID__ V-38583

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50384r3_rule

__STIG ID__ RHEL-06-000067

__Rule Title__

`The system boot loader configuration file(s) must have mode 0600 or less permissive.`

__Discussion__

```
Proper permissions ensure that only the root user can modify important boot parameters.
```

__Check Content__

```
To check the permissions of "/boot/grub/grub.conf", run the command:

$ sudo ls -lL /boot/grub/grub.conf

If properly configured, the output should indicate the following permissions: "-rw-------"
If it does not, this is a finding. 
```

__Fix Text__

```
File permissions for "/boot/grub/grub.conf" should be set to 600, which is the default. To properly set the permissions of "/boot/grub/grub.conf", run the command:

# chmod 600 /boot/grub/grub.conf

Boot partitions based on VFAT, NTFS, or other non-standard configurations may require alternative measures.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000204

__Vuln ID__ V-38584

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50385r1_rule

__STIG ID__ RHEL-06-000204

__Rule Title__

`The xinetd service must be uninstalled if no network services utilizing it are enabled.`

__Discussion__

```
Removing the "xinetd" package decreases the risk of the xinetd service's accidental (or intentional) activation.
```

__Check Content__

```
If network services are using the xinetd service, this is not applicable.

Run the following command to determine if the "xinetd" package is installed: 

# rpm -q xinetd


If the package is installed, this is a finding.
```

__Fix Text__

```
The "xinetd" package can be uninstalled with the following command: 

# yum erase xinetd
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000068

__Vuln ID__ V-38585

__Severity__ medium

__Group Title__ SRG-OS-000080

__Rule ID__ SV-50386r3_rule

__STIG ID__ RHEL-06-000068

__Rule Title__

`The system boot loader must require authentication.`

__Discussion__

```
Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.
```

__Check Content__

```
To verify the boot loader password has been set and encrypted, run the following command: 

# grep password /boot/grub/grub.conf

The output should show the following: 

password --encrypted $6$[rest-of-the-password-hash]

If it does not, this is a finding.
```

__Fix Text__

```
The grub boot loader should have password protection enabled to protect boot-time settings. To do so, select a password and then generate a hash from it by running the following command: 

# grub-crypt --sha-512

When prompted to enter a password, insert the following line into "/boot/grub/grub.conf" immediately after the header comments. (Use the output from "grub-crypt" as the value of [password-hash]): 

password --encrypted [password-hash]
```

__CCI__

```
CCI-000213
The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
NIST SP 800-53 :: AC-3
NIST SP 800-53A :: AC-3.1
NIST SP 800-53 Revision 4 :: AC-3


```


### RHEL-06-000069

__Vuln ID__ V-38586

__Severity__ medium

__Group Title__ SRG-OS-000080

__Rule ID__ SV-50387r1_rule

__STIG ID__ RHEL-06-000069

__Rule Title__

`The system must require authentication upon booting into single-user and maintenance modes.`

__Discussion__

```
This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.
```

__Check Content__

```
To check if authentication is required for single-user mode, run the following command: 

$ grep SINGLE /etc/sysconfig/init

The output should be the following: 

SINGLE=/sbin/sulogin


If the output is different, this is a finding.
```

__Fix Text__

```
Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected. 

To require entry of the root password even if the system is started in single-user mode, add or correct the following line in the file "/etc/sysconfig/init": 

SINGLE=/sbin/sulogin
```

__CCI__

```
CCI-000213
The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
NIST SP 800-53 :: AC-3
NIST SP 800-53A :: AC-3.1
NIST SP 800-53 Revision 4 :: AC-3


```


### RHEL-06-000206

__Vuln ID__ V-38587

__Severity__ high

__Group Title__ SRG-OS-000095

__Rule ID__ SV-50388r1_rule

__STIG ID__ RHEL-06-000206

__Rule Title__

`The telnet-server package must not be installed.`

__Discussion__

```
Removing the "telnet-server" package decreases the risk of the unencrypted telnet service's accidental (or intentional) activation.

Mitigation:  If the telnet-server package is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
```

__Check Content__

```
Run the following command to determine if the "telnet-server" package is installed: 

# rpm -q telnet-server


If the package is installed, this is a finding.
```

__Fix Text__

```
The "telnet-server" package can be uninstalled with the following command: 

# yum erase telnet-server
```

__CCI__

```
CCI-000381
The organization configures the information system to provide only essential capabilities.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (ii)
NIST SP 800-53 Revision 4 :: CM-7 a


```


### RHEL-06-000070

__Vuln ID__ V-38588

__Severity__ medium

__Group Title__ SRG-OS-000080

__Rule ID__ SV-50389r1_rule

__STIG ID__ RHEL-06-000070

__Rule Title__

`The system must not permit interactive boot.`

__Discussion__

```
Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.
```

__Check Content__

```
To check whether interactive boot is disabled, run the following command: 

$ grep PROMPT /etc/sysconfig/init

If interactive boot is disabled, the output will show: 

PROMPT=no


If it does not, this is a finding.
```

__Fix Text__

```
To disable the ability for users to perform interactive startups, edit the file "/etc/sysconfig/init". Add or correct the line: 

PROMPT=no

The "PROMPT" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.
```

__CCI__

```
CCI-000213
The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
NIST SP 800-53 :: AC-3
NIST SP 800-53A :: AC-3.1
NIST SP 800-53 Revision 4 :: AC-3


```


### RHEL-06-000211

__Vuln ID__ V-38589

__Severity__ high

__Group Title__ SRG-OS-000129

__Rule ID__ SV-50390r2_rule

__STIG ID__ RHEL-06-000211

__Rule Title__

`The telnet daemon must not be running.`

__Discussion__

```
The telnet protocol uses unencrypted network communication, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network. The telnet protocol is also subject to man-in-the-middle attacks.

Mitigation:  If an enabled telnet daemon is configured to only allow encrypted sessions, such as with Kerberos or the use of encrypted network tunnels, the risk of exposing sensitive information is mitigated.
```

__Check Content__

```
To check that the "telnet" service is disabled in system boot configuration, run the following command: 

# chkconfig "telnet" --list

Output should indicate the "telnet" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "telnet" --list
telnet         off
OR
error reading information on service telnet: No such file or directory


If the service is running, this is a finding.
```

__Fix Text__

```
The "telnet" service can be disabled with the following command: 

# chkconfig telnet off
```

__CCI__

```
CCI-000888
The organization employs cryptographic mechanisms to protect the integrity and confidentiality of non-local maintenance and diagnostic communications.
NIST SP 800-53 :: MA-4 (6)
NIST SP 800-53A :: MA-4 (6).1


```


### RHEL-06-000071

__Vuln ID__ V-38590

__Severity__ low

__Group Title__ SRG-OS-000030

__Rule ID__ SV-50391r1_rule

__STIG ID__ RHEL-06-000071

__Rule Title__

`The system must allow locking of the console screen in text mode.`

__Discussion__

```
Installing "screen" ensures a console locking capability is available for users who may need to suspend console logins.
```

__Check Content__

```
Run the following command to determine if the "screen" package is installed: 

# rpm -q screen


If the package is not installed, this is a finding.
```

__Fix Text__

```
To enable console screen locking when in text mode, install the "screen" package: 

# yum install screen

Instruct users to begin new terminal sessions with the following command: 

$ screen

The console can now be locked with the following key combination: 

ctrl+a x
```

__CCI__

```
CCI-000058
The information system provides the capability for users to directly initiate session lock mechanisms.
NIST SP 800-53 :: AC-11 a
NIST SP 800-53A :: AC-11
NIST SP 800-53 Revision 4 :: AC-11 a


```


### RHEL-06-000213

__Vuln ID__ V-38591

__Severity__ high

__Group Title__ SRG-OS-000095

__Rule ID__ SV-50392r1_rule

__STIG ID__ RHEL-06-000213

__Rule Title__

`The rsh-server package must not be installed.`

__Discussion__

```
The "rsh-server" package provides several obsolete and insecure network services. Removing it decreases the risk of those services' accidental (or intentional) activation.
```

__Check Content__

```
Run the following command to determine if the "rsh-server" package is installed: 

# rpm -q rsh-server


If the package is installed, this is a finding.
```

__Fix Text__

```
The "rsh-server" package can be uninstalled with the following command: 

# yum erase rsh-server
```

__CCI__

```
CCI-000381
The organization configures the information system to provide only essential capabilities.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (ii)
NIST SP 800-53 Revision 4 :: CM-7 a


```


### RHEL-06-000356

__Vuln ID__ V-38592

__Severity__ medium

__Group Title__ SRG-OS-000022

__Rule ID__ SV-50393r4_rule

__STIG ID__ RHEL-06-000356

__Rule Title__

`The system must require administrator action to unlock an account locked by excessive failed login attempts.`

__Discussion__

```
Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks. Ensuring that an administrator is involved in unlocking locked accounts draws appropriate attention to such situations.
```

__Check Content__

```
To ensure the failed password attempt policy is configured correctly, run the following command: 

# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth

The output should show "unlock_time=<some-large-number>"; the largest acceptable value is 604800 seconds (one week). 
If that is not the case, this is a finding.
```

__Fix Text__

```
To configure the system to lock out accounts after a number of incorrect logon attempts and require an administrator to unlock the account using "pam_faillock.so", modify the content of both "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" as follows: 

Add the following line immediately before the "pam_unix.so" statement in the "AUTH" section: 

auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately after the "pam_unix.so" statement in the "AUTH" section: 

auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900

Add the following line immediately before the "pam_unix.so" statement in the "ACCOUNT" section: 

account required pam_faillock.so

Note that any updates made to "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" may be overwritten by the "authconfig" program.  The "authconfig" program should not be used.
```

__CCI__

```
CCI-000047
The information system delays next login prompt according to organization defined delay algorithm, when the maximum number of unsuccessful attempts is exceeded, automatically locks the account/node for an organization defined time period or locks the account/node until released by an Administrator IAW organizational policy.
NIST SP 800-53 :: AC-7 b
NIST SP 800-53A :: AC-7.1 (iv)


```


### RHEL-06-000073

__Vuln ID__ V-38593

__Severity__ medium

__Group Title__ SRG-OS-000228

__Rule ID__ SV-50394r3_rule

__STIG ID__ RHEL-06-000073

__Rule Title__

`The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, console login prompts.`

__Discussion__

```
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
```

__Check Content__

```
To check if the system login banner is compliant, run the following command: 

$ cat /etc/issue


Note: The full text banner must be implemented unless there are character limitations that prevent the display of the full DoD logon banner.

If the required DoD logon banner is not displayed, this is a finding.

```

__Fix Text__

```
To configure the system login banner: 

Edit "/etc/issue". Replace the default text with a message compliant with the local site policy or a legal disclaimer. The DoD required text is either: 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

If the device cannot support the full DoD logon banner due to character limitations, the following text can be used:

"I've read & consent to terms in IS user agreem't."
```

__CCI__

```
CCI-001384
The information system, for publicly accessible systems, displays system use information organization-defined conditions before granting further access.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (i)
NIST SP 800-53 Revision 4 :: AC-8 c 1

CCI-001385
The information system, for publicly accessible systems, displays references, if any, to monitoring that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001386
The information system for publicly accessible systems displays references, if any, to recording that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001387
The information system for publicly accessible systems displays references, if any, to auditing that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001388
The information system, for publicly accessible systems, includes a description of the authorized uses of the system.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (iii)
NIST SP 800-53 Revision 4 :: AC-8 c 3


```


### RHEL-06-000214

__Vuln ID__ V-38594

__Severity__ high

__Group Title__ SRG-OS-000033

__Rule ID__ SV-50395r2_rule

__STIG ID__ RHEL-06-000214

__Rule Title__

`The rshd service must not be running.`

__Discussion__

```
The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
```

__Check Content__

```
To check that the "rsh" service is disabled in system boot configuration, run the following command:

# chkconfig "rsh" --list

Output should indicate the "rsh" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rsh" --list
rsh off
OR
error reading information on service rsh: No such file or directory


If the service is running, this is a finding.
```

__Fix Text__

```
The "rsh" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rsh" service can be disabled with the following command: 

# chkconfig rsh off
```

__CCI__

```
CCI-000068
The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.
NIST SP 800-53 :: AC-17 (2)
NIST SP 800-53A :: AC-17 (2).1
NIST SP 800-53 Revision 4 :: AC-17 (2)


```


### RHEL-06-000349

__Vuln ID__ V-38595

__Severity__ medium

__Group Title__ SRG-OS-000105

__Rule ID__ SV-50396r3_rule

__STIG ID__ RHEL-06-000349

__Rule Title__

`The system must be configured to require the use of a CAC, PIV compliant hardware token, or Alternate Logon Token (ALT) for authentication.`

__Discussion__

```
Smart card login provides two-factor authentication stronger than that provided by a username/password combination. Smart cards leverage a PKI (public key infrastructure) in order to provide and verify credentials.
```

__Check Content__

```
Interview the SA to determine if all accounts not exempted by policy are using CAC authentication. For DoD systems, the following systems and accounts are exempt from using smart card (CAC) authentication: 

Standalone systems
Application accounts
Temporary employee accounts, such as students or interns, who cannot easily receive a CAC or PIV
Operational tactical locations that are not collocated with RAPIDS workstations to issue CAC or ALT
Test systems, such as those with an Interim Approval to Test (IATT) and use a separate VPN, firewall, or security measure preventing access to network and system components from outside the protection boundary documented in the IATT.



If non-exempt accounts are not using CAC authentication, this is a finding.
```

__Fix Text__

```
To enable smart card authentication, consult the documentation at:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Managing_Smart_Cards/enabling-smart-card-login.html

For guidance on enabling SSH to authenticate against a Common Access Card (CAC), consult documentation at:

https://access.redhat.com/solutions/82273
```

__CCI__

```
CCI-000765
The information system implements multifactor authentication for network access to privileged accounts.
NIST SP 800-53 :: IA-2 (1)
NIST SP 800-53A :: IA-2 (1).1
NIST SP 800-53 Revision 4 :: IA-2 (1)


```


### RHEL-06-000078

__Vuln ID__ V-38596

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50397r2_rule

__STIG ID__ RHEL-06-000078

__Rule Title__

`The system must implement virtual address space randomization.`

__Discussion__

```
Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return oriented programming (ROP) techniques.
```

__Check Content__

```
The status of the "kernel.randomize_va_space" kernel parameter can be queried by running the following commands: 

$ sysctl kernel.randomize_va_space
$ grep kernel.randomize_va_space /etc/sysctl.conf

The output of the command should indicate a value of at least "1" (preferably "2"). If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
If the correct value is not returned, this is a finding.
```

__Fix Text__

```
To set the runtime status of the "kernel.randomize_va_space" kernel parameter, run the following command: 

# sysctl -w kernel.randomize_va_space=2

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

kernel.randomize_va_space = 2
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000079

__Vuln ID__ V-38597

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50398r2_rule

__STIG ID__ RHEL-06-000079

__Rule Title__

`The system must limit the ability of processes to have simultaneous write and execute access to memory.`

__Discussion__

```
ExecShield uses the segmentation feature on all x86 systems to prevent execution in memory higher than a certain address. It writes an address as a limit in the code segment descriptor, to control where code can be executed, on a per-process basis. When the kernel places a process's memory regions such as the stack and heap higher than this address, the hardware prevents execution in that address range.
```

__Check Content__

```
The status of the "kernel.exec-shield" kernel parameter can be queried by running the following command: 

$ sysctl kernel.exec-shield
$ grep kernel.exec-shield /etc/sysctl.conf

The output of the command should indicate a value of "1". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf". 
If the correct value is not returned, this is a finding.
```

__Fix Text__

```
To set the runtime status of the "kernel.exec-shield" kernel parameter, run the following command: 

# sysctl -w kernel.exec-shield=1

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

kernel.exec-shield = 1
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000216

__Vuln ID__ V-38598

__Severity__ high

__Group Title__ SRG-OS-000033

__Rule ID__ SV-50399r2_rule

__STIG ID__ RHEL-06-000216

__Rule Title__

`The rexecd service must not be running.`

__Discussion__

```
The rexec service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
```

__Check Content__

```
To check that the "rexec" service is disabled in system boot configuration, run the following command:

# chkconfig "rexec" --list

Output should indicate the "rexec" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rexec" --list
rexec off
OR
error reading information on service rexec: No such file or directory


If the service is running, this is a finding.
```

__Fix Text__

```
The "rexec" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rexec" service can be disabled with the following command: 

# chkconfig rexec off
```

__CCI__

```
CCI-000068
The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.
NIST SP 800-53 :: AC-17 (2)
NIST SP 800-53A :: AC-17 (2).1
NIST SP 800-53 Revision 4 :: AC-17 (2)


```


### RHEL-06-000348

__Vuln ID__ V-38599

__Severity__ medium

__Group Title__ SRG-OS-000023

__Rule ID__ SV-50400r2_rule

__STIG ID__ RHEL-06-000348

__Rule Title__

`The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.`

__Discussion__

```
This setting will cause the system greeting banner to be used for FTP connections as well.
```

__Check Content__

```
To verify this configuration, run the following command: 

grep "banner_file" /etc/vsftpd/vsftpd.conf

The output should show the value of "banner_file" is set to "/etc/issue", an example of which is shown below. 

# grep "banner_file" /etc/vsftpd/vsftpd.conf
banner_file=/etc/issue


If it does not, this is a finding.
```

__Fix Text__

```
Edit the vsftpd configuration file, which resides at "/etc/vsftpd/vsftpd.conf" by default. Add or correct the following configuration options. 

banner_file=/etc/issue

Restart the vsftpd daemon.

# service vsftpd restart
```

__CCI__

```
CCI-000048
The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
NIST SP 800-53 :: AC-8 a
NIST SP 800-53A :: AC-8.1 (ii)
NIST SP 800-53 Revision 4 :: AC-8 a


```


### RHEL-06-000080

__Vuln ID__ V-38600

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50401r2_rule

__STIG ID__ RHEL-06-000080

__Rule Title__

`The system must not send ICMPv4 redirects by default.`

__Discussion__

```
Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.
```

__Check Content__

```
The status of the "net.ipv4.conf.default.send_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.default.send_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.default.send_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.default.send_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.default.send_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.default.send_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000081

__Vuln ID__ V-38601

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50402r2_rule

__STIG ID__ RHEL-06-000081

__Rule Title__

`The system must not send ICMPv4 redirects from any interface.`

__Discussion__

```
Sending ICMP redirects permits the system to instruct other systems to update their routing information. The ability to send ICMP redirects is only appropriate for systems acting as routers.
```

__Check Content__

```
The status of the "net.ipv4.conf.all.send_redirects" kernel parameter can be queried by running the following command:

$ sysctl net.ipv4.conf.all.send_redirects

The output of the command should indicate a value of "0". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in "/etc/sysctl.conf".

$ grep net.ipv4.conf.all.send_redirects /etc/sysctl.conf

If the correct value is not returned, this is a finding. 
```

__Fix Text__

```
To set the runtime status of the "net.ipv4.conf.all.send_redirects" kernel parameter, run the following command: 

# sysctl -w net.ipv4.conf.all.send_redirects=0

If this is not the system's default value, add the following line to "/etc/sysctl.conf": 

net.ipv4.conf.all.send_redirects = 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000218

__Vuln ID__ V-38602

__Severity__ high

__Group Title__ SRG-OS-000248

__Rule ID__ SV-50403r2_rule

__STIG ID__ RHEL-06-000218

__Rule Title__

`The rlogind service must not be running.`

__Discussion__

```
The rlogin service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
```

__Check Content__

```
 
To check that the "rlogin" service is disabled in system boot configuration, run the following command:

# chkconfig "rlogin" --list

Output should indicate the "rlogin" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "rlogin" --list
rlogin off
OR
error reading information on service rlogin: No such file or directory


If the service is running, this is a finding.
```

__Fix Text__

```
The "rlogin" service, which is available with the "rsh-server" package and runs as a service through xinetd, should be disabled. The "rlogin" service can be disabled with the following command: 

# chkconfig rlogin off
```

__CCI__

```
CCI-001436
The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.
NIST SP 800-53 :: AC-17 (8)
NIST SP 800-53A :: AC-17 (8).1 (ii)


```


### RHEL-06-000220

__Vuln ID__ V-38603

__Severity__ medium

__Group Title__ SRG-OS-000095

__Rule ID__ SV-50404r1_rule

__STIG ID__ RHEL-06-000220

__Rule Title__

`The ypserv package must not be installed.`

__Discussion__

```
Removing the "ypserv" package decreases the risk of the accidental (or intentional) activation of NIS or NIS+ services.
```

__Check Content__

```
Run the following command to determine if the "ypserv" package is installed: 

# rpm -q ypserv


If the package is installed, this is a finding.
```

__Fix Text__

```
The "ypserv" package can be uninstalled with the following command: 

# yum erase ypserv
```

__CCI__

```
CCI-000381
The organization configures the information system to provide only essential capabilities.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (ii)
NIST SP 800-53 Revision 4 :: CM-7 a


```


### RHEL-06-000221

__Vuln ID__ V-38604

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50405r2_rule

__STIG ID__ RHEL-06-000221

__Rule Title__

`The ypbind service must not be running.`

__Discussion__

```
Disabling the "ypbind" service ensures the system is not acting as a client in a NIS or NIS+ domain.
```

__Check Content__

```
To check that the "ypbind" service is disabled in system boot configuration, run the following command: 

# chkconfig "ypbind" --list

Output should indicate the "ypbind" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "ypbind" --list
"ypbind" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ypbind" is disabled through current runtime configuration: 

# service ypbind status

If the service is disabled the command will return the following output: 

ypbind is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "ypbind" service, which allows the system to act as a client in a NIS or NIS+ domain, should be disabled. The "ypbind" service can be disabled with the following commands: 

# chkconfig ypbind off
# service ypbind stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000224

__Vuln ID__ V-38605

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50406r2_rule

__STIG ID__ RHEL-06-000224

__Rule Title__

`The cron service must be running.`

__Discussion__

```
Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential.
```

__Check Content__

```
Run the following command to determine the current status of the "crond" service: 

# service crond status

If the service is enabled, it should return the following: 

crond is running...


If the service is not running, this is a finding.
```

__Fix Text__

```
The "crond" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The "crond" service can be enabled with the following commands: 

# chkconfig crond on
# service crond start
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000222

__Vuln ID__ V-38606

__Severity__ medium

__Group Title__ SRG-OS-000095

__Rule ID__ SV-50407r2_rule

__STIG ID__ RHEL-06-000222

__Rule Title__

`The tftp-server package must not be installed unless required.`

__Discussion__

```
Removing the "tftp-server" package decreases the risk of the accidental (or intentional) activation of tftp services.
```

__Check Content__

```
Run the following command to determine if the "tftp-server" package is installed: 

# rpm -q tftp-server


If the package is installed, this is a finding.
```

__Fix Text__

```
The "tftp-server" package can be removed with the following command: 

# yum erase tftp-server
```

__CCI__

```
CCI-000381
The organization configures the information system to provide only essential capabilities.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (ii)
NIST SP 800-53 Revision 4 :: CM-7 a


```


### RHEL-06-000227

__Vuln ID__ V-38607

__Severity__ high

__Group Title__ SRG-OS-000112

__Rule ID__ SV-50408r1_rule

__STIG ID__ RHEL-06-000227

__Rule Title__

`The SSH daemon must be configured to use only the SSHv2 protocol.`

__Discussion__

```
SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.
```

__Check Content__

```
To check which SSH protocol version is allowed, run the following command: 

# grep Protocol /etc/ssh/sshd_config

If configured properly, output should be 

Protocol 2


If it is not, this is a finding.
```

__Fix Text__

```
Only SSH protocol version 2 connections should be permitted. The default setting in "/etc/ssh/sshd_config" is correct, and can be verified by ensuring that the following line appears: 

Protocol 2
```

__CCI__

```
CCI-000774
The information system uses organization defined replay-resistant authentication mechanisms for network access to privileged accounts.
NIST SP 800-53 :: IA-2 (8)
NIST SP 800-53A :: IA-2 (8).1 (ii)


```


### RHEL-06-000230

__Vuln ID__ V-38608

__Severity__ low

__Group Title__ SRG-OS-000163

__Rule ID__ SV-50409r1_rule

__STIG ID__ RHEL-06-000230

__Rule Title__

`The SSH daemon must set a timeout interval on idle sessions.`

__Discussion__

```
Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.
```

__Check Content__

```
Run the following command to see what the timeout interval is: 

# grep ClientAliveInterval /etc/ssh/sshd_config

If properly configured, the output should be: 

ClientAliveInterval 900


If it is not, this is a finding.
```

__Fix Text__

```
SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out. 

To set an idle timeout interval, edit the following line in "/etc/ssh/sshd_config" as follows: 

ClientAliveInterval [interval]

The timeout [interval] is given in seconds. To have a timeout of 15 minutes, set [interval] to 900. 

If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.
```

__CCI__

```
CCI-001133
The information system terminates the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.
NIST SP 800-53 :: SC-10
NIST SP 800-53A :: SC-10.1 (ii)
NIST SP 800-53 Revision 4 :: SC-10


```


### RHEL-06-000223

__Vuln ID__ V-38609

__Severity__ medium

__Group Title__ SRG-OS-000248

__Rule ID__ SV-50410r2_rule

__STIG ID__ RHEL-06-000223

__Rule Title__

`The TFTP service must not be running.`

__Discussion__

```
Disabling the "tftp" service ensures the system is not acting as a tftp server, which does not provide encryption or authentication.
```

__Check Content__

```
To check that the "tftp" service is disabled in system boot configuration, run the following command:

# chkconfig "tftp" --list

Output should indicate the "tftp" service has either not been installed, or has been disabled, as shown in the example below:

# chkconfig "tftp" --list
tftp off
OR
error reading information on service tftp: No such file or directory


If the service is running, this is a finding.
```

__Fix Text__

```
The "tftp" service should be disabled. The "tftp" service can be disabled with the following command: 

# chkconfig tftp off
```

__CCI__

```
CCI-001436
The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.
NIST SP 800-53 :: AC-17 (8)
NIST SP 800-53A :: AC-17 (8).1 (ii)


```


### RHEL-06-000231

__Vuln ID__ V-38610

__Severity__ low

__Group Title__ SRG-OS-000126

__Rule ID__ SV-50411r1_rule

__STIG ID__ RHEL-06-000231

__Rule Title__

`The SSH daemon must set a timeout count on idle sessions.`

__Discussion__

```
This ensures a user login will be terminated as soon as the "ClientAliveCountMax" is reached.
```

__Check Content__

```
To ensure the SSH idle timeout will occur when the "ClientAliveCountMax" is set, run the following command: 

# grep ClientAliveCountMax /etc/ssh/sshd_config

If properly configured, output should be: 

ClientAliveCountMax 0


If it is not, this is a finding.
```

__Fix Text__

```
To ensure the SSH idle timeout occurs precisely when the "ClientAliveCountMax" is set, edit "/etc/ssh/sshd_config" as follows: 

ClientAliveCountMax 0
```

__CCI__

```
CCI-000879
The organization terminates sessions and network connections when nonlocal maintenance is completed.
NIST SP 800-53 :: MA-4 e
NIST SP 800-53A :: MA-4.1 (vi)
NIST SP 800-53 Revision 4 :: MA-4 e


```


### RHEL-06-000234

__Vuln ID__ V-38611

__Severity__ medium

__Group Title__ SRG-OS-000106

__Rule ID__ SV-50412r1_rule

__STIG ID__ RHEL-06-000234

__Rule Title__

`The SSH daemon must ignore .rhosts files.`

__Discussion__

```
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
```

__Check Content__

```
To determine how the SSH daemon's "IgnoreRhosts" option is set, run the following command: 

# grep -i IgnoreRhosts /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "yes" is returned, then the required value is set. 
If the required value is not set, this is a finding.
```

__Fix Text__

```
SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via ".rhosts" files. 

To ensure this behavior is disabled, add or correct the following line in "/etc/ssh/sshd_config": 

IgnoreRhosts yes
```

__CCI__

```
CCI-000766
The information system implements multifactor authentication for network access to non-privileged accounts.
NIST SP 800-53 :: IA-2 (2)
NIST SP 800-53A :: IA-2 (2).1
NIST SP 800-53 Revision 4 :: IA-2 (2)


```


### RHEL-06-000236

__Vuln ID__ V-38612

__Severity__ medium

__Group Title__ SRG-OS-000106

__Rule ID__ SV-50413r1_rule

__STIG ID__ RHEL-06-000236

__Rule Title__

`The SSH daemon must not allow host-based authentication.`

__Discussion__

```
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
```

__Check Content__

```
To determine how the SSH daemon's "HostbasedAuthentication" option is set, run the following command: 

# grep -i HostbasedAuthentication /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.
```

__Fix Text__

```
SSH's cryptographic host-based authentication is more secure than ".rhosts" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization. 

To disable host-based authentication, add or correct the following line in "/etc/ssh/sshd_config": 

HostbasedAuthentication no
```

__CCI__

```
CCI-000766
The information system implements multifactor authentication for network access to non-privileged accounts.
NIST SP 800-53 :: IA-2 (2)
NIST SP 800-53A :: IA-2 (2).1
NIST SP 800-53 Revision 4 :: IA-2 (2)


```


### RHEL-06-000237

__Vuln ID__ V-38613

__Severity__ medium

__Group Title__ SRG-OS-000109

__Rule ID__ SV-50414r1_rule

__STIG ID__ RHEL-06-000237

__Rule Title__

`The system must not permit root logins using remote access programs such as ssh.`

__Discussion__

```
Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password.
```

__Check Content__

```
To determine how the SSH daemon's "PermitRootLogin" option is set, run the following command: 

# grep -i PermitRootLogin /etc/ssh/sshd_config

If a line indicating "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.
```

__Fix Text__

```
The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in "/etc/ssh/sshd_config": 

PermitRootLogin no
```

__CCI__

```
CCI-000770
The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.
NIST SP 800-53 :: IA-2 (5) (b)
NIST SP 800-53A :: IA-2 (5).2 (ii)
NIST SP 800-53 Revision 4 :: IA-2 (5)


```


### RHEL-06-000239

__Vuln ID__ V-38614

__Severity__ high

__Group Title__ SRG-OS-000106

__Rule ID__ SV-50415r1_rule

__STIG ID__ RHEL-06-000239

__Rule Title__

`The SSH daemon must not allow authentication using an empty password.`

__Discussion__

```
Configuring this setting for the SSH daemon provides additional assurance that remote login via SSH will require a password, even in the event of misconfiguration elsewhere.
```

__Check Content__

```
To determine how the SSH daemon's "PermitEmptyPasswords" option is set, run the following command: 

# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

If no line, a commented line, or a line indicating the value "no" is returned, then the required value is set. 
If the required value is not set, this is a finding.
```

__Fix Text__

```
To explicitly disallow remote login from accounts with empty passwords, add or correct the following line in "/etc/ssh/sshd_config": 

PermitEmptyPasswords no

Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.
```

__CCI__

```
CCI-000766
The information system implements multifactor authentication for network access to non-privileged accounts.
NIST SP 800-53 :: IA-2 (2)
NIST SP 800-53A :: IA-2 (2).1
NIST SP 800-53 Revision 4 :: IA-2 (2)


```


### RHEL-06-000240

__Vuln ID__ V-38615

__Severity__ medium

__Group Title__ SRG-OS-000023

__Rule ID__ SV-50416r1_rule

__STIG ID__ RHEL-06-000240

__Rule Title__

`The SSH daemon must be configured with the Department of Defense (DoD) login banner.`

__Discussion__

```
The warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure usage of a banner that does not provide easy attribution.
```

__Check Content__

```
To determine how the SSH daemon's "Banner" option is set, run the following command: 

# grep -i Banner /etc/ssh/sshd_config

If a line indicating /etc/issue is returned, then the required value is set. 
If the required value is not set, this is a finding.
```

__Fix Text__

```
To enable the warning banner and ensure it is consistent across the system, add or correct the following line in "/etc/ssh/sshd_config": 

Banner /etc/issue

Another section contains information on how to create an appropriate system-wide warning banner.
```

__CCI__

```
CCI-000048
The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
NIST SP 800-53 :: AC-8 a
NIST SP 800-53A :: AC-8.1 (ii)
NIST SP 800-53 Revision 4 :: AC-8 a


```


### RHEL-06-000241

__Vuln ID__ V-38616

__Severity__ low

__Group Title__ SRG-OS-000242

__Rule ID__ SV-50417r1_rule

__STIG ID__ RHEL-06-000241

__Rule Title__

`The SSH daemon must not permit user environment settings.`

__Discussion__

```
SSH environment options potentially allow users to bypass access restriction in some configurations.
```

__Check Content__

```
To ensure users are not able to present environment daemons, run the following command: 

# grep PermitUserEnvironment /etc/ssh/sshd_config

If properly configured, output should be: 

PermitUserEnvironment no


If it is not, this is a finding.
```

__Fix Text__

```
To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in "/etc/ssh/sshd_config": 

PermitUserEnvironment no
```

__CCI__

```
CCI-001414
The information system enforces approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.
NIST SP 800-53 :: AC-4
NIST SP 800-53A :: AC-4.1 (iii)
NIST SP 800-53 Revision 4 :: AC-4


```


### RHEL-06-000243

__Vuln ID__ V-38617

__Severity__ medium

__Group Title__ SRG-OS-000169

__Rule ID__ SV-50418r1_rule

__STIG ID__ RHEL-06-000243

__Rule Title__

`The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.`

__Discussion__

```
Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.
```

__Check Content__

```
Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep Ciphers /etc/ssh/sshd_config

The output should contain only those ciphers which are FIPS-approved, namely, the AES and 3DES ciphers. 
If that is not the case, this is a finding.
```

__Fix Text__

```
Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The following line in "/etc/ssh/sshd_config" demonstrates use of FIPS-approved ciphers: 

Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc

The man page "sshd_config(5)" contains a list of supported ciphers.
```

__CCI__

```
CCI-001144
The information system implements required cryptographic protections using cryptographic modules that comply with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
NIST SP 800-53 :: SC-13
NIST SP 800-53A :: SC-13.1


```


### RHEL-06-000246

__Vuln ID__ V-38618

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50419r2_rule

__STIG ID__ RHEL-06-000246

__Rule Title__

`The avahi service must be disabled.`

__Discussion__

```
Because the Avahi daemon service keeps an open network port, it is subject to network attacks. Its functionality is convenient but is only appropriate if the local network can be trusted.
```

__Check Content__

```
To check that the "avahi-daemon" service is disabled in system boot configuration, run the following command: 

# chkconfig "avahi-daemon" --list

Output should indicate the "avahi-daemon" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "avahi-daemon" --list
"avahi-daemon" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "avahi-daemon" is disabled through current runtime configuration: 

# service avahi-daemon status

If the service is disabled the command will return the following output: 

avahi-daemon is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "avahi-daemon" service can be disabled with the following commands: 

# chkconfig avahi-daemon off
# service avahi-daemon stop
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000347

__Vuln ID__ V-38619

__Severity__ medium

__Group Title__ SRG-OS-000073

__Rule ID__ SV-50420r2_rule

__STIG ID__ RHEL-06-000347

__Rule Title__

`There must be no .netrc files on the system.`

__Discussion__

```
Unencrypted passwords for remote FTP servers may be stored in ".netrc" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.
```

__Check Content__

```
To check the system for the existence of any ".netrc" files, run the following command: 

$ sudo find /root /home -xdev -name .netrc

If any .netrc files exist, this is a finding.
```

__Fix Text__

```
The ".netrc" files contain logon information used to auto-logon into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any ".netrc" files should be removed.
```

__CCI__

```
CCI-000196
The information system, for password-based authentication, stores only encrypted representations of passwords.
NIST SP 800-53 :: IA-5 (1) (c)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (c)


```


### RHEL-06-000247

__Vuln ID__ V-38620

__Severity__ medium

__Group Title__ SRG-OS-000056

__Rule ID__ SV-50421r1_rule

__STIG ID__ RHEL-06-000247

__Rule Title__

`The system clock must be synchronized continuously, or at least daily.`

__Discussion__

```
Enabling the "ntpd" service ensures that the "ntpd" service will be running and that the system will synchronize its time to any servers specified. This is important whether the system is configured to be a client (and synchronize only its own clock) or it is also acting as an NTP server to other systems. Synchronizing time is essential for authentication services such as Kerberos, but it is also important for maintaining accurate logs and auditing possible security breaches.
```

__Check Content__

```
Run the following command to determine the current status of the "ntpd" service: 

# service ntpd status

If the service is enabled, it should return the following: 

ntpd is running...


If the service is not running, this is a finding.
```

__Fix Text__

```
The "ntpd" service can be enabled with the following command: 

# chkconfig ntpd on
# service ntpd start
```

__CCI__

```
CCI-000160
The information system synchronizes internal information system clocks on an organization defined frequency with an organization defined authoritative time source.
NIST SP 800-53 :: AU-8 (1)
NIST SP 800-53A :: AU-8 (1).1 (iii)


```


### RHEL-06-000248

__Vuln ID__ V-38621

__Severity__ medium

__Group Title__ SRG-OS-000056

__Rule ID__ SV-50422r1_rule

__STIG ID__ RHEL-06-000248

__Rule Title__

`The system clock must be synchronized to an authoritative DoD time source.`

__Discussion__

```
Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.
```

__Check Content__

```
A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file. 

/etc/ntp.conf

In the file, there should be a section similar to the following: 

# --- OUR TIMESERVERS -----
server [ntpserver]


If this is not the case, this is a finding.
```

__Fix Text__

```
To specify a remote NTP server for time synchronization, edit the file "/etc/ntp.conf". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver. 

server [ntpserver]

This instructs the NTP software to contact that remote server to obtain time data.
```

__CCI__

```
CCI-000160
The information system synchronizes internal information system clocks on an organization defined frequency with an organization defined authoritative time source.
NIST SP 800-53 :: AU-8 (1)
NIST SP 800-53A :: AU-8 (1).1 (iii)


```


### RHEL-06-000249

__Vuln ID__ V-38622

__Severity__ medium

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50423r2_rule

__STIG ID__ RHEL-06-000249

__Rule Title__

`Mail relaying must be restricted.`

__Discussion__

```
This ensures "postfix" accepts mail messages (such as cron job reports) from the local system only, and not from the network, which protects it from network attack.
```

__Check Content__

```
If the system is an authorized mail relay host, this is not applicable. 

Run the following command to ensure postfix accepts mail messages from only the local system: 

$ grep inet_interfaces /etc/postfix/main.cf

If properly configured, the output should show only "localhost". 
If it does not, this is a finding.
```

__Fix Text__

```
Edit the file "/etc/postfix/main.cf" to ensure that only the following "inet_interfaces" line appears: 

inet_interfaces = localhost
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000135

__Vuln ID__ V-38623

__Severity__ medium

__Group Title__ SRG-OS-000206

__Rule ID__ SV-50424r2_rule

__STIG ID__ RHEL-06-000135

__Rule Title__

`All rsyslog-generated log files must have mode 0600 or less permissive.`

__Discussion__

```
Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.
```

__Check Content__

```
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions: 

$ ls -l [LOGFILE]

The permissions should be 600, or more restrictive. Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.

If the permissions are not correct, this is a finding.
```

__Fix Text__

```
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in "/etc/rsyslog.conf" and typically all appear in "/var/log". For each log file [LOGFILE] referenced in "/etc/rsyslog.conf", run the following command to inspect the file's permissions:

$ ls -l [LOGFILE]

If the permissions are not 600 or more restrictive, run the following command to correct this:

# chmod 0600 [LOGFILE]
```

__CCI__

```
CCI-001314
The information system reveals error messages only to organization-defined personnel or roles.
NIST SP 800-53 :: SI-11 c
NIST SP 800-53A :: SI-11.1 (iv)
NIST SP 800-53 Revision 4 :: SI-11 b


```


### RHEL-06-000138

__Vuln ID__ V-38624

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50425r1_rule

__STIG ID__ RHEL-06-000138

__Rule Title__

`System logs must be rotated daily.`

__Discussion__

```
Log files that are not properly rotated run the risk of growing so large that they fill up the /var/log partition. Valuable logging information could be lost if the /var/log partition becomes full.
```

__Check Content__

```
Run the following commands to determine the current status of the "logrotate" service: 

# grep logrotate /var/log/cron*

If the logrotate service is not run on a daily basis by cron, this is a finding.
```

__Fix Text__

```
The "logrotate" service should be installed or reinstalled if it is not installed and operating properly, by running the following command:

# yum reinstall logrotate
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000256

__Vuln ID__ V-38627

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50428r2_rule

__STIG ID__ RHEL-06-000256

__Rule Title__

`The openldap-servers package must not be installed unless required.`

__Discussion__

```
Unnecessary packages should not be installed to decrease the attack surface of the system.
```

__Check Content__

```
To verify the "openldap-servers" package is not installed, run the following command: 

$ rpm -q openldap-servers

The output should show the following. 

package openldap-servers is not installed


If it does not, this is a finding.
```

__Fix Text__

```
The "openldap-servers" package should be removed if not in use.

# yum erase openldap-servers

The openldap-servers RPM is not installed by default on RHEL6 machines. It is needed only by the OpenLDAP server, not by the clients which use LDAP for authentication. If the system is not intended for use as an LDAP Server it should be removed.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000145

__Vuln ID__ V-38628

__Severity__ medium

__Group Title__ SRG-OS-000255

__Rule ID__ SV-50429r2_rule

__STIG ID__ RHEL-06-000145

__Rule Title__

`The operating system must produce audit records containing sufficient information to establish the identity of any user/subject associated with the event.`

__Discussion__

```
Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.
```

__Check Content__

```
Run the following command to determine the current status of the "auditd" service: 

# service auditd status

If the service is enabled, it should return the following: 

auditd is running...


If the service is not running, this is a finding.
```

__Fix Text__

```
The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands: 

# chkconfig auditd on
# service auditd start
```

__CCI__

```
CCI-001487
The information system generates audit records containing information that establishes the identity of any individuals or subjects associated with the event.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3


```


### RHEL-06-000257

__Vuln ID__ V-38629

__Severity__ medium

__Group Title__ SRG-OS-000029

__Rule ID__ SV-50430r3_rule

__STIG ID__ RHEL-06-000257

__Rule Title__

`The graphical desktop environment must set the idle timeout to no more than 15 minutes.`

__Discussion__

```
Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

To check the current idle time-out value, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay

If properly configured, the output should be "15". 

If it is not, this is a finding.
```

__Fix Text__

```
Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes: 

# gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type int \
--set /apps/gnome-screensaver/idle_delay 15
```

__CCI__

```
CCI-000057
The information system initiates a session lock after the organization-defined time period of inactivity.
NIST SP 800-53 :: AC-11 a
NIST SP 800-53A :: AC-11.1 (ii)
NIST SP 800-53 Revision 4 :: AC-11 a


```


### RHEL-06-000258

__Vuln ID__ V-38630

__Severity__ medium

__Group Title__ SRG-OS-000029

__Rule ID__ SV-50431r3_rule

__STIG ID__ RHEL-06-000258

__Rule Title__

`The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.`

__Discussion__

```
Enabling idle activation of the screen saver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

To check the screensaver mandatory use status, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled

If properly configured, the output should be "true". 

If it is not, this is a finding.
```

__Fix Text__

```
Run the following command to activate the screensaver in the GNOME desktop after a period of inactivity: 

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gnome-screensaver/idle_activation_enabled true
```

__CCI__

```
CCI-000057
The information system initiates a session lock after the organization-defined time period of inactivity.
NIST SP 800-53 :: AC-11 a
NIST SP 800-53A :: AC-11.1 (ii)
NIST SP 800-53 Revision 4 :: AC-11 a


```


### RHEL-06-000148

__Vuln ID__ V-38631

__Severity__ medium

__Group Title__ SRG-OS-000032

__Rule ID__ SV-50432r2_rule

__STIG ID__ RHEL-06-000148

__Rule Title__

`The operating system must employ automated mechanisms to facilitate the monitoring and control of remote access methods.`

__Discussion__

```
Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.
```

__Check Content__

```
Run the following command to determine the current status of the "auditd" service: 

# service auditd status

If the service is enabled, it should return the following: 

auditd is running...


If the service is not running, this is a finding.
```

__Fix Text__

```
The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands: 

# chkconfig auditd on
# service auditd start
```

__CCI__

```
CCI-000067
The information system monitors remote access methods.
NIST SP 800-53 :: AC-17 (1)
NIST SP 800-53A :: AC-17 (1).1
NIST SP 800-53 Revision 4 :: AC-17 (1)


```


### RHEL-06-000154

__Vuln ID__ V-38632

__Severity__ medium

__Group Title__ SRG-OS-000037

__Rule ID__ SV-50433r2_rule

__STIG ID__ RHEL-06-000154

__Rule Title__

`The operating system must produce audit records containing sufficient information to establish what type of events occurred.`

__Discussion__

```
Ensuring the "auditd" service is active ensures audit records generated by the kernel can be written to disk, or that appropriate actions will be taken if other obstacles exist.
```

__Check Content__

```
Run the following command to determine the current status of the "auditd" service: 

# service auditd status

If the service is enabled, it should return the following: 

auditd is running...


If the service is not running, this is a finding.
```

__Fix Text__

```
The "auditd" service is an essential userspace component of the Linux Auditing System, as it is responsible for writing audit records to disk. The "auditd" service can be enabled with the following commands: 

# chkconfig auditd on
# service auditd start
```

__CCI__

```
CCI-000130
The information system generates audit records containing information that establishes what type of event occurred.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3


```


### RHEL-06-000160

__Vuln ID__ V-38633

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50434r1_rule

__STIG ID__ RHEL-06-000160

__Rule Title__

`The system must set a maximum audit log file size.`

__Discussion__

```
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine how much data the system will retain in each audit log file: "# grep max_log_file /etc/audit/auditd.conf" 

max_log_file = 6


If the system audit data threshold hasn't been properly set up, this is a finding.
```

__Fix Text__

```
Determine the amount of audit data (in megabytes) which should be retained in each log file. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting the correct value for [STOREMB]: 

max_log_file = [STOREMB]

Set the value to "6" (MB) or higher for general-purpose systems. Larger values, of course, support retention of even more audit data.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000161

__Vuln ID__ V-38634

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50435r2_rule

__STIG ID__ RHEL-06-000161

__Rule Title__

`The system must rotate audit log files that reach the maximum file size.`

__Discussion__

```
Automatically rotating logs (by setting this to "rotate") minimizes the chances of the system unexpectedly running out of disk space by being overwhelmed with log data. However, for systems that must never discard log data, or which use external processes to transfer it and reclaim space, "keep_logs" can be employed.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to rotate logs when they reach their maximum size:

# grep max_log_file_action /etc/audit/auditd.conf
max_log_file_action = rotate

If the "keep_logs" option is configured for the "max_log_file_action" line in "/etc/audit/auditd.conf" and an alternate process is in place to ensure audit data does not overwhelm local audit storage, this is not a finding.

If the system has not been properly set up to rotate audit logs, this is a finding.
```

__Fix Text__

```
The default action to take when the logs reach their maximum size is to rotate the log files, discarding the oldest one. To configure the action taken by "auditd", add or correct the line in "/etc/audit/auditd.conf": 

max_log_file_action = [ACTION]

Possible values for [ACTION] are described in the "auditd.conf" man page. These include: 

"ignore"
"syslog"
"suspend"
"rotate"
"keep_logs"


Set the "[ACTION]" to "rotate" to ensure log rotation occurs. This is the default. The setting is case-insensitive.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000165

__Vuln ID__ V-38635

__Severity__ low

__Group Title__ SRG-OS-000062

__Rule ID__ SV-50436r3_rule

__STIG ID__ RHEL-06-000165

__Rule Title__

`The audit system must be configured to audit all attempts to alter system time through adjtimex.`

__Discussion__

```
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
```

__Check Content__

```
To determine if the system is configured to audit calls to the "adjtimex" system call, run the following command:

$ sudo grep -w "adjtimex" /etc/audit/audit.rules

If the system is configured to audit this activity, it will return a line. 

If the system is not configured to audit time changes, this is a finding.
```

__Fix Text__

```
On a 32-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b32 -S adjtimex -k audit_time_rules

On a 64-bit system, add the following to "/etc/audit/audit.rules": 

# audit_time_rules
-a always,exit -F arch=b64 -S adjtimex -k audit_time_rules

The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport. Multiple system calls can be defined on the same line to save space if desired, but is not required. See an example of multiple combined syscalls: 

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k audit_time_rules
```

__CCI__

```
CCI-000169
The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.
NIST SP 800-53 :: AU-12 a
NIST SP 800-53A :: AU-12.1 (ii)
NIST SP 800-53 Revision 4 :: AU-12 a


```


### RHEL-06-000159

__Vuln ID__ V-38636

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50437r1_rule

__STIG ID__ RHEL-06-000159

__Rule Title__

`The system must retain enough rotated audit logs to cover the required log retention period.`

__Discussion__

```
The total storage for audit log files must be large enough to retain log information over the period required. This is a function of the maximum log file size and the number of logs retained.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine how many logs the system is configured to retain after rotation: "# grep num_logs /etc/audit/auditd.conf" 

num_logs = 5


If the overall system log file(s) retention hasn't been properly set up, this is a finding.
```

__Fix Text__

```
Determine how many log files "auditd" should retain when it rotates logs. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [NUMLOGS] with the correct value: 

num_logs = [NUMLOGS]

Set the value to 5 for general-purpose systems. Note that values less than 2 result in no log rotation.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000281

__Vuln ID__ V-38637

__Severity__ medium

__Group Title__ SRG-OS-000278

__Rule ID__ SV-50438r2_rule

__STIG ID__ RHEL-06-000281

__Rule Title__

`The system package management tool must verify contents of all files associated with the audit package.`

__Discussion__

```
The hash on important files like audit system executables should match the information given by the RPM database. Audit executables  with erroneous hashes could be a sign of nefarious activity on the system.
```

__Check Content__

```
The following command will list which audit files on the system have file hashes different from what is expected by the RPM database. 

# rpm -V audit | awk '$1 ~ /..5/ && $2 != "c"'


If there is output, this is a finding.
```

__Fix Text__

```
The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database: 

# rpm -V audit | grep '^..5'

A "c" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories. 

rpm -Uvh [affected_package]

OR 

yum reinstall [affected_package]
```

__CCI__

```
CCI-001496
The information system implements cryptographic mechanisms to protect the integrity of audit tools.
NIST SP 800-53 :: AU-9 (3)
NIST SP 800-53A :: AU-9 (3).1
NIST SP 800-53 Revision 4 :: AU-9 (3)


```


### RHEL-06-000259

__Vuln ID__ V-38638

__Severity__ medium

__Group Title__ SRG-OS-000029

__Rule ID__ SV-50439r3_rule

__STIG ID__ RHEL-06-000259

__Rule Title__

`The graphical desktop environment must have automatic lock enabled.`

__Discussion__

```
Enabling the activation of the screen lock after an idle period ensures password entry will be required in order to access the system, preventing access by passersby.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable. 

To check the status of the idle screen lock activation, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/lock_enabled

If properly configured, the output should be "true". 
If it is not, this is a finding.
```

__Fix Text__

```
Run the following command to activate locking of the screensaver in the GNOME desktop when it is activated: 

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gnome-screensaver/lock_enabled true
```

__CCI__

```
CCI-000057
The information system initiates a session lock after the organization-defined time period of inactivity.
NIST SP 800-53 :: AC-11 a
NIST SP 800-53A :: AC-11.1 (ii)
NIST SP 800-53 Revision 4 :: AC-11 a


```


### RHEL-06-000260

__Vuln ID__ V-38639

__Severity__ low

__Group Title__ SRG-OS-000031

__Rule ID__ SV-50440r3_rule

__STIG ID__ RHEL-06-000260

__Rule Title__

`The system must display a publicly-viewable pattern during a graphical desktop environment session lock.`

__Discussion__

```
Setting the screensaver mode to blank-only conceals the contents of the display from passersby.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable. 

To ensure the screensaver is configured to be blank, run the following command: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode

If properly configured, the output should be "blank-only". 
If it is not, this is a finding.
```

__Fix Text__

```
Run the following command to set the screensaver mode in the GNOME desktop to a blank screen: 

# gconftool-2 \
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gnome-screensaver/mode blank-only
```

__CCI__

```
CCI-000060
The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image.
NIST SP 800-53 :: AC-11 (1)
NIST SP 800-53A :: AC-11 (1).1
NIST SP 800-53 Revision 4 :: AC-11 (1)


```


### RHEL-06-000261

__Vuln ID__ V-38640

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50441r2_rule

__STIG ID__ RHEL-06-000261

__Rule Title__

`The Automatic Bug Reporting Tool (abrtd) service must not be running.`

__Discussion__

```
Mishandling crash data could expose sensitive information about vulnerabilities in software executing on the local machine, as well as sensitive information from within a process's address space or registers.
```

__Check Content__

```
To check that the "abrtd" service is disabled in system boot configuration, run the following command: 

# chkconfig "abrtd" --list

Output should indicate the "abrtd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "abrtd" --list
"abrtd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "abrtd" is disabled through current runtime configuration: 

# service abrtd status

If the service is disabled the command will return the following output: 

abrtd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The Automatic Bug Reporting Tool ("abrtd") daemon collects and reports crash data when an application crash is detected. Using a variety of plugins, abrtd can email crash reports to system administrators, log crash reports to files, or forward crash reports to a centralized issue tracking system such as RHTSupport. The "abrtd" service can be disabled with the following commands: 

# chkconfig abrtd off
# service abrtd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000262

__Vuln ID__ V-38641

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50442r3_rule

__STIG ID__ RHEL-06-000262

__Rule Title__

`The atd service must be disabled.`

__Discussion__

```
The "atd" service could be used by an unsophisticated insider to carry out activities outside of a normal login session, which could complicate accountability. Furthermore, the need to schedule tasks with "at" or "batch" is not common.
```

__Check Content__

```
If the system requires the use of the "atd" service to support an organizational requirement, this is not applicable.

To check that the "atd" service is disabled in system boot configuration, run the following command: 

# chkconfig "atd" --list

Output should indicate the "atd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "atd" --list
"atd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "atd" is disabled through current runtime configuration: 

# service atd status

If the service is disabled the command will return the following output: 

atd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "at" and "batch" commands can be used to schedule tasks that are meant to be executed only once. This allows delayed execution in a manner similar to cron, except that it is not recurring. The daemon "atd" keeps track of tasks scheduled via "at" and "batch", and executes them at the specified time. The "atd" service can be disabled with the following commands: 

# chkconfig atd off
# service atd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000346

__Vuln ID__ V-38642

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50443r1_rule

__STIG ID__ RHEL-06-000346

__Rule Title__

`The system default umask for daemons must be 027 or 022.`

__Discussion__

```
The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions.
```

__Check Content__

```
To check the value of the "umask", run the following command: 

$ grep umask /etc/init.d/functions

The output should show either "022" or "027". 
If it does not, this is a finding.
```

__Fix Text__

```
The file "/etc/init.d/functions" includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for [UMASK] appropriately: 

umask [UMASK]

Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000282

__Vuln ID__ V-38643

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50444r3_rule

__STIG ID__ RHEL-06-000282

__Rule Title__

`There must be no world-writable files on the system.`

__Discussion__

```
Data in world-writable files can be modified by any user on the system. In almost all circumstances, files can be configured using a combination of user and group permissions to support whatever legitimate access is needed without the risk caused by world-writable files.
```

__Check Content__

```
To find world-writable files, run the following command for each local partition [PART], excluding special filesystems such as /selinux, /proc, or /sys: 

# find [PART] -xdev -type f -perm -002

If there is output, this is a finding.
```

__Fix Text__

```
It is generally a good idea to remove global (other) write access to a file when it is discovered. However, check with documentation for specific applications before making changes. Also, monitor for recurring world-writable files, as these may be symptoms of a misconfigured application or user account.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000265

__Vuln ID__ V-38644

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50445r2_rule

__STIG ID__ RHEL-06-000265

__Rule Title__

`The ntpdate service must not be running.`

__Discussion__

```
The "ntpdate" service may only be suitable for systems which are rebooted frequently enough that clock drift does not cause problems between reboots. In any event, the functionality of the ntpdate service is now available in the ntpd program and should be considered deprecated.
```

__Check Content__

```
To check that the "ntpdate" service is disabled in system boot configuration, run the following command: 

# chkconfig "ntpdate" --list

Output should indicate the "ntpdate" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "ntpdate" --list
"ntpdate" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "ntpdate" is disabled through current runtime configuration: 

# service ntpdate status

If the service is disabled the command will return the following output: 

ntpdate is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The ntpdate service sets the local hardware clock by polling NTP servers when the system boots. It synchronizes to the NTP servers listed in "/etc/ntp/step-tickers" or "/etc/ntp.conf" and then sets the local hardware clock to the newly synchronized system time. The "ntpdate" service can be disabled with the following commands: 

# chkconfig ntpdate off
# service ntpdate stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000345

__Vuln ID__ V-38645

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50446r1_rule

__STIG ID__ RHEL-06-000345

__Rule Title__

`The system default umask in /etc/login.defs must be 077.`

__Discussion__

```
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
```

__Check Content__

```
Verify the "umask" setting is configured correctly in the "/etc/login.defs" file by running the following command: 

# grep -i "umask" /etc/login.defs

All output must show the value of "umask" set to 077, as shown in the below: 

# grep -i "umask" /etc/login.defs
UMASK 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
```

__Fix Text__

```
To ensure the default umask controlled by "/etc/login.defs" is set properly, add or correct the "umask" setting in "/etc/login.defs" to read as follows: 

UMASK 077
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000266

__Vuln ID__ V-38646

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50447r2_rule

__STIG ID__ RHEL-06-000266

__Rule Title__

`The oddjobd service must not be running.`

__Discussion__

```
The "oddjobd" service may provide necessary functionality in some environments but it can be disabled if it is not needed. Execution of tasks by privileged programs, on behalf of unprivileged ones, has traditionally been a source of privilege escalation security issues.
```

__Check Content__

```
To check that the "oddjobd" service is disabled in system boot configuration, run the following command: 

# chkconfig "oddjobd" --list

Output should indicate the "oddjobd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "oddjobd" --list
"oddjobd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "oddjobd" is disabled through current runtime configuration: 

# service oddjobd status

If the service is disabled the command will return the following output: 

oddjobd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "oddjobd" service exists to provide an interface and access control mechanism through which specified privileged tasks can run tasks for unprivileged client applications. Communication with "oddjobd" is through the system message bus. The "oddjobd" service can be disabled with the following commands: 

# chkconfig oddjobd off
# service oddjobd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000344

__Vuln ID__ V-38647

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50448r1_rule

__STIG ID__ RHEL-06-000344

__Rule Title__

`The system default umask in /etc/profile must be 077.`

__Discussion__

```
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
```

__Check Content__

```
Verify the "umask" setting is configured correctly in the "/etc/profile" file by running the following command: 

# grep "umask" /etc/profile

All output must show the value of "umask" set to 077, as shown in the below: 

# grep "umask" /etc/profile
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
```

__Fix Text__

```
To ensure the default umask controlled by "/etc/profile" is set properly, add or correct the "umask" setting in "/etc/profile" to read as follows: 

umask 077
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000267

__Vuln ID__ V-38648

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50449r2_rule

__STIG ID__ RHEL-06-000267

__Rule Title__

`The qpidd service must not be running.`

__Discussion__

```
The qpidd service is automatically installed when the "base" package selection is selected during installation. The qpidd service listens for network connections which increases the attack surface of the system. If the system is not intended to receive AMQP traffic then the "qpidd" service is not needed and should be disabled or removed.
```

__Check Content__

```
To check that the "qpidd" service is disabled in system boot configuration, run the following command: 

# chkconfig "qpidd" --list

Output should indicate the "qpidd" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "qpidd" --list
"qpidd" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "qpidd" is disabled through current runtime configuration: 

# service qpidd status

If the service is disabled the command will return the following output: 

qpidd is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "qpidd" service provides high speed, secure, guaranteed delivery services. It is an implementation of the Advanced Message Queuing Protocol. By default the qpidd service will bind to port 5672 and listen for connection attempts. The "qpidd" service can be disabled with the following commands: 

# chkconfig qpidd off
# service qpidd stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000343

__Vuln ID__ V-38649

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50450r1_rule

__STIG ID__ RHEL-06-000343

__Rule Title__

`The system default umask for the csh shell must be 077.`

__Discussion__

```
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
```

__Check Content__

```
Verify the "umask" setting is configured correctly in the "/etc/csh.cshrc" file by running the following command: 

# grep "umask" /etc/csh.cshrc

All output must show the value of "umask" set to 077, as shown in the below: 

# grep "umask" /etc/csh.cshrc
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
```

__Fix Text__

```
To ensure the default umask for users of the C shell is set properly, add or correct the "umask" setting in "/etc/csh.cshrc" to read as follows: 

umask 077
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000268

__Vuln ID__ V-38650

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50451r2_rule

__STIG ID__ RHEL-06-000268

__Rule Title__

`The rdisc service must not be running.`

__Discussion__

```
General-purpose systems typically have their network and routing information configured statically by a system administrator. Workstations or some special-purpose systems often use DHCP (instead of IRDP) to retrieve dynamic network configuration information.
```

__Check Content__

```
To check that the "rdisc" service is disabled in system boot configuration, run the following command: 

# chkconfig "rdisc" --list

Output should indicate the "rdisc" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "rdisc" --list
"rdisc" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "rdisc" is disabled through current runtime configuration: 

# service rdisc status

If the service is disabled the command will return the following output: 

rdisc is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "rdisc" service implements the client side of the ICMP Internet Router Discovery Protocol (IRDP), which allows discovery of routers on the local subnet. If a router is discovered then the local routing table is updated with a corresponding default route. By default this daemon is disabled. The "rdisc" service can be disabled with the following commands: 

# chkconfig rdisc off
# service rdisc stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000342

__Vuln ID__ V-38651

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50452r1_rule

__STIG ID__ RHEL-06-000342

__Rule Title__

`The system default umask for the bash shell must be 077.`

__Discussion__

```
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
```

__Check Content__

```
Verify the "umask" setting is configured correctly in the "/etc/bashrc" file by running the following command: 

# grep "umask" /etc/bashrc

All output must show the value of "umask" set to 077, as shown below: 

# grep "umask" /etc/bashrc
umask 077
umask 077


If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
```

__Fix Text__

```
To ensure the default umask for users of the Bash shell is set properly, add or correct the "umask" setting in "/etc/bashrc" to read as follows: 

umask 077
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000269

__Vuln ID__ V-38652

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50453r2_rule

__STIG ID__ RHEL-06-000269

__Rule Title__

`Remote file systems must be mounted with the nodev option.`

__Discussion__

```
Legitimate device files should only exist in the /dev directory. NFS mounts should not present device files to users.
```

__Check Content__

```
To verify the "nodev" option is configured for all NFS mounts, run the following command: 

$ mount | grep "nfs "

All NFS mounts should show the "nodev" setting in parentheses, along with other mount options. 
If the setting does not show, this is a finding.
```

__Fix Text__

```
Add the "nodev" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000341

__Vuln ID__ V-38653

__Severity__ high

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50454r1_rule

__STIG ID__ RHEL-06-000341

__Rule Title__

`The snmpd service must not use a default password.`

__Discussion__

```
Presence of the default SNMP password enables querying of different system aspects and could result in unauthorized knowledge of the system.
```

__Check Content__

```
To ensure the default password is not set, run the following command: 

# grep -v "^#" /etc/snmp/snmpd.conf| grep public

There should be no output. 
If there is output, this is a finding.
```

__Fix Text__

```
Edit "/etc/snmp/snmpd.conf", remove default community string "public". Upon doing that, restart the SNMP service: 

# service snmpd restart
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000270

__Vuln ID__ V-38654

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50455r2_rule

__STIG ID__ RHEL-06-000270

__Rule Title__

`Remote file systems must be mounted with the nosuid option.`

__Discussion__

```
NFS mounts should not present suid binaries to users. Only vendor-supplied suid executables should be installed to their default location on the local filesystem.
```

__Check Content__

```
To verify the "nosuid" option is configured for all NFS mounts, run the following command: 

$ mount | grep nfs

All NFS mounts should show the "nosuid" setting in parentheses, along with other mount options. 
If the setting does not show, this is a finding.
```

__Fix Text__

```
Add the "nosuid" option to the fourth column of "/etc/fstab" for the line which controls mounting of any NFS mounts.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000271

__Vuln ID__ V-38655

__Severity__ low

__Group Title__ SRG-OS-000035

__Rule ID__ SV-50456r1_rule

__STIG ID__ RHEL-06-000271

__Rule Title__

`The noexec option must be added to removable media partitions.`

__Discussion__

```
Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.
```

__Check Content__

```
To verify that binaries cannot be directly executed from removable media, run the following command: 

# grep noexec /etc/fstab

The output should show "noexec" in use. 
If it does not, this is a finding.
```

__Fix Text__

```
The "noexec" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The "noexec" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of any removable media partitions.
```

__CCI__

```
CCI-000087
The organization disables information system functionality that provides the capability for automatic execution of code on mobile devices without user direction.
NIST SP 800-53 :: AC-19 e
NIST SP 800-53A :: AC-19.1 (v)


```


### RHEL-06-000272

__Vuln ID__ V-38656

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50457r1_rule

__STIG ID__ RHEL-06-000272

__Rule Title__

`The system must use SMB client signing for connecting to samba servers using smbclient.`

__Discussion__

```
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
```

__Check Content__

```
To verify that Samba clients running smbclient must use packet signing, run the following command: 

# grep signing /etc/samba/smb.conf

The output should show: 

client signing = mandatory


If it is not, this is a finding.
```

__Fix Text__

```
To require samba clients running "smbclient" to use packet signing, add the following to the "[global]" section of the Samba configuration file in "/etc/samba/smb.conf": 

client signing = mandatory

Requiring samba clients such as "smbclient" to use packet signing ensures they can only communicate with servers that support packet signing.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000273

__Vuln ID__ V-38657

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50458r2_rule

__STIG ID__ RHEL-06-000273

__Rule Title__

`The system must use SMB client signing for connecting to samba servers using mount.cifs.`

__Discussion__

```
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
```

__Check Content__

```
If Samba is not in use, this is not applicable.

To verify that Samba clients using mount.cifs must use packet signing, run the following command: 

# grep sec /etc/fstab /etc/mtab

The output should show either "krb5i" or "ntlmv2i" in use. 
If it does not, this is a finding.
```

__Fix Text__

```
Require packet signing of clients who mount Samba shares using the "mount.cifs" program (e.g., those who specify shares in "/etc/fstab"). To do so, ensure signing options (either "sec=krb5i" or "sec=ntlmv2i") are used. 

See the "mount.cifs(8)" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000274

__Vuln ID__ V-38658

__Severity__ medium

__Group Title__ SRG-OS-000077

__Rule ID__ SV-50459r4_rule

__STIG ID__ RHEL-06-000274

__Rule Title__

`The system must prohibit the reuse of passwords within five iterations.`

__Discussion__

```
Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.
```

__Check Content__

```
To verify the password reuse setting is compliant, run the following command: 

# grep remember /etc/pam.d/system-auth

The output must be a line beginning with "password required pam_pwhistory.so" and ending with "remember=5".

If the line is commented out, the line does not contain the specified elements, or the value for "remember" is less than 5, this is a finding.
```

__Fix Text__

```
Do not allow users to reuse recent passwords. This can be accomplished by using the "remember" option for the "pam_pwhistory" PAM module. In the file "/etc/pam.d/system-auth", append "remember=5" to the line which refers to the "pam_pwhistory.so" module, as shown: 

password required pam_pwhistory.so [existing_options] remember=5

The DoD requirement is five passwords.   
```

__CCI__

```
CCI-000200
The information system prohibits password reuse for the organization defined number of generations.
NIST SP 800-53 :: IA-5 (1) (e)
NIST SP 800-53A :: IA-5 (1).1 (v)
NIST SP 800-53 Revision 4 :: IA-5 (1) (e)


```


### RHEL-06-000275

__Vuln ID__ V-38659

__Severity__ low

__Group Title__ SRG-OS-000131

__Rule ID__ SV-50460r2_rule

__STIG ID__ RHEL-06-000275

__Rule Title__

`The operating system must employ cryptographic mechanisms to protect information in storage.`

__Discussion__

```
The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
```

__Check Content__

```
Determine if encryption must be used to protect data on the system. 
If encryption must be used and is not employed, this is a finding.
```

__Fix Text__

```
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
```

__CCI__

```
CCI-001019
The organization employs cryptographic mechanisms to protect information in storage.
NIST SP 800-53 :: MP-4 (1)
NIST SP 800-53A :: MP-4 (1).1


```


### RHEL-06-000340

__Vuln ID__ V-38660

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50461r1_rule

__STIG ID__ RHEL-06-000340

__Rule Title__

`The snmpd service must use only SNMP protocol version 3 or newer.`

__Discussion__

```
Earlier versions of SNMP are considered insecure, as they potentially allow unauthorized access to detailed system management information.

```

__Check Content__

```
To ensure only SNMPv3 or newer is used, run the following command: 

# grep 'v1\|v2c\|com2sec' /etc/snmp/snmpd.conf | grep -v '^#'

There should be no output. 
If there is output, this is a finding.
```

__Fix Text__

```
Edit "/etc/snmp/snmpd.conf", removing any references to "v1", "v2c", or "com2sec". Upon doing that, restart the SNMP service: 

# service snmpd restart
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000276

__Vuln ID__ V-38661

__Severity__ low

__Group Title__ SRG-OS-000185

__Rule ID__ SV-50462r2_rule

__STIG ID__ RHEL-06-000276

__Rule Title__

`The operating system must protect the confidentiality and integrity of data at rest. `

__Discussion__

```
The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
```

__Check Content__

```
Determine if encryption must be used to protect data on the system. 
If encryption must be used and is not employed, this is a finding.
```

__Fix Text__

```
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
```

__CCI__

```
CCI-001199
The information system protects the confidentiality and/or integrity of organization-defined information at rest.
NIST SP 800-53 :: SC-28
NIST SP 800-53A :: SC-28.1
NIST SP 800-53 Revision 4 :: SC-28


```


### RHEL-06-000277

__Vuln ID__ V-38662

__Severity__ low

__Group Title__ SRG-OS-000230

__Rule ID__ SV-50463r2_rule

__STIG ID__ RHEL-06-000277

__Rule Title__

`The operating system must employ cryptographic mechanisms to prevent unauthorized disclosure of data at rest unless otherwise protected by alternative physical measures.`

__Discussion__

```
The risk of a system's physical compromise, particularly mobile systems such as laptops, places its data at risk of compromise. Encrypting this data mitigates the risk of its loss if the system is lost.
```

__Check Content__

```
Determine if encryption must be used to protect data on the system. 
If encryption must be used and is not employed, this is a finding.
```

__Fix Text__

```
Red Hat Enterprise Linux 6 natively supports partition encryption through the Linux Unified Key Setup-on-disk-format (LUKS) technology. The easiest way to encrypt a partition is during installation time. 

For manual installations, select the "Encrypt" checkbox during partition creation to encrypt the partition. When this option is selected the system will prompt for a passphrase to use in decrypting the partition. The passphrase will subsequently need to be entered manually every time the system boots. 

For automated/unattended installations, it is possible to use Kickstart by adding the "--encrypted" and "--passphrase=" options to the definition of each partition to be encrypted. For example, the following line would encrypt the root partition: 

part / --fstype=ext3 --size=100 --onpart=hda1 --encrypted --passphrase=[PASSPHRASE]

Any [PASSPHRASE] is stored in the Kickstart in plaintext, and the Kickstart must then be protected accordingly. Omitting the "--passphrase=" option from the partition definition will cause the installer to pause and interactively ask for the passphrase during installation. 

Detailed information on encrypting partitions using LUKS can be found on the Red Hat Documentation web site:

https://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/Security_Guide/sect-Security_Guide-LUKS_Disk_Encryption.html
```

__CCI__

```
CCI-001200
The organization employs cryptographic mechanisms to prevent unauthorized disclosure of information at rest unless otherwise protected by alternative physical measures.
NIST SP 800-53 :: SC-28 (1)
NIST SP 800-53A :: SC-28 (1).1 (i)


```


### RHEL-06-000278

__Vuln ID__ V-38663

__Severity__ medium

__Group Title__ SRG-OS-000256

__Rule ID__ SV-50464r1_rule

__STIG ID__ RHEL-06-000278

__Rule Title__

`The system package management tool must verify permissions on all files and directories associated with the audit package.`

__Discussion__

```
Permissions on audit binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which audit files on the system have permissions different from what is expected by the RPM database: 

# rpm -V audit | grep '^.M'

If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:

# rpm -q --queryformat "[%{FILENAMES} %{FILEMODES:perms}\n]" audit | grep  [filename]
# ls -lL [filename]

If the existing permissions are more permissive than those expected by RPM, this is a finding.
```

__Fix Text__

```
The RPM package management system can restore file access permissions of the audit package files and directories. The following command will update audit files with permissions different from what is expected by the RPM database: 

# rpm --setperms audit
```

__CCI__

```
CCI-001493
The information system protects audit tools from unauthorized access.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000279

__Vuln ID__ V-38664

__Severity__ medium

__Group Title__ SRG-OS-000257

__Rule ID__ SV-50465r1_rule

__STIG ID__ RHEL-06-000279

__Rule Title__

`The system package management tool must verify ownership on all files and directories associated with the audit package.`

__Discussion__

```
Ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which audit files on the system have ownership different from what is expected by the RPM database: 

# rpm -V audit | grep '^.....U'


If there is output, this is a finding.
```

__Fix Text__

```
The RPM package management system can restore file ownership of the audit package files and directories. The following command will update audit files with ownership different from what is expected by the RPM database: 

# rpm --setugids audit
```

__CCI__

```
CCI-001494
The information system protects audit tools from unauthorized modification.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000280

__Vuln ID__ V-38665

__Severity__ medium

__Group Title__ SRG-OS-000258

__Rule ID__ SV-50466r1_rule

__STIG ID__ RHEL-06-000280

__Rule Title__

`The system package management tool must verify group-ownership on all files and directories associated with the audit package.`

__Discussion__

```
Group-ownership of audit binaries and configuration files that is incorrect could allow an unauthorized user to gain privileges that they should not have. The group-ownership set by the vendor should be maintained. Any deviations from this baseline should be investigated.
```

__Check Content__

```
The following command will list which audit files on the system have group-ownership different from what is expected by the RPM database: 

# rpm -V audit | grep '^......G'


If there is output, this is a finding.
```

__Fix Text__

```
The RPM package management system can restore file group-ownership of the audit package files and directories. The following command will update audit files with group-ownership different from what is expected by the RPM database: 

# rpm --setugids audit
```

__CCI__

```
CCI-001495
The information system protects audit tools from unauthorized deletion.
NIST SP 800-53 :: AU-9
NIST SP 800-53A :: AU-9.1
NIST SP 800-53 Revision 4 :: AU-9


```


### RHEL-06-000284

__Vuln ID__ V-38666

__Severity__ high

__Group Title__ SRG-OS-000270

__Rule ID__ SV-50467r2_rule

__STIG ID__ RHEL-06-000284

__Rule Title__

`The system must use and update a DoD-approved virus scan program.`

__Discussion__

```
Virus scanning software can be used to detect if a system has been compromised by computer viruses, as well as to limit their spread to other systems.
```

__Check Content__

```
Inspect the system for a cron job or system service which executes a virus scanning tool regularly.
To verify the McAfee VSEL system service is operational, run the following command:

# /etc/init.d/nails status

To check on the age of uvscan virus definition files, run the following command:

# cd /opt/NAI/LinuxShield/engine/dat
# ls -la avvscan.dat avvnames.dat avvclean.dat

If virus scanning software does not run continuously, or at least daily, or has signatures that are out of date, this is a finding. 
```

__Fix Text__

```
Install virus scanning software, which uses signatures to search for the presence of viruses on the filesystem. 

The McAfee VirusScan Enterprise for Linux virus scanning tool is provided for DoD systems. Ensure virus definition files are no older than 7 days, or their last release. 

Configure the virus scanning software to perform scans dynamically on all accessed files. If this is not possible, configure the system to scan all altered files on the system on a daily basis. If the system processes inbound SMTP mail, configure the virus scanner to scan all received mail. 
```

__CCI__

```
CCI-001668
The organization employs malicious code protection mechanisms at workstations, servers, or mobile computing devices on the network to detect and eradicate malicious code transported by electronic mail, electronic mail attachments, web accesses, removable media, or other common means or inserted through the exploitation of information system vulnerabilities.
NIST SP 800-53 :: SI-3 a
NIST SP 800-53A :: SI-3.1 (ii)


```


### RHEL-06-000285

__Vuln ID__ V-38667

__Severity__ medium

__Group Title__ SRG-OS-000196

__Rule ID__ SV-50468r3_rule

__STIG ID__ RHEL-06-000285

__Rule Title__

`The system must have a host-based intrusion detection tool installed.`

__Discussion__

```
Adding host-based intrusion detection tools can provide the capability to automatically take actions in response to malicious behavior, which can provide additional agility in reacting to network threats. These tools also often include a reporting capability to provide network awareness of system, which may not otherwise exist in an organization's systems management regime.
```

__Check Content__

```
Ask the SA or ISSO if a host-based intrusion detection application is loaded on the system. Per OPORD 16-0080 the preferred intrusion detection system is McAfee HBSS available through Cybercom.

If another host-based intrusion detection application is in use, such as SELinux, this must be documented and approved by the local Authorizing Official.

Procedure:
Examine the system to see if the Host Intrusion Prevention System (HIPS) is installed:

# rpm -qa | grep MFEhiplsm

Verify that the McAfee HIPS module is active on the system:

# ps -ef | grep -i "hipclient"

If the MFEhiplsm package is not installed, check for another intrusion detection system:

# find / -name <daemon name>

Where <daemon name> is the name of the primary application daemon to determine if the application is loaded on the system.

Determine if the application is active on the system:

# ps -ef | grep -i <daemon name>

If the MFEhiplsm package is not installed and an alternate host-based intrusion detection application has not been documented for use, this is a finding.

If no host-based intrusion detection system is installed and running on the system, this is a finding.

```

__Fix Text__

```
Install and enable the latest McAfee HIPS package, available from Cybercom.

If the system does not support the McAfee HIPS package, install and enable a supported intrusion detection system application and document its use with the Authorizing Official.

```

__CCI__

```
CCI-001263
The information system provides near real-time alerts when any of the  organization defined list of compromise or potential compromise indicators occurs.
NIST SP 800-53 :: SI-4 (5)
NIST SP 800-53A :: SI-4 (5).1 (ii)


```


### RHEL-06-000286

__Vuln ID__ V-38668

__Severity__ high

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50469r3_rule

__STIG ID__ RHEL-06-000286

__Rule Title__

`The x86 Ctrl-Alt-Delete key sequence must be disabled.`

__Discussion__

```
A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
```

__Check Content__

```
To ensure the system is configured to log a message instead of rebooting the system when Ctrl-Alt-Delete is pressed, ensure the following line is in "/etc/init/control-alt-delete.override":

exec /usr/bin/logger -p security.info "Ctrl-Alt-Delete pressed"

If the system is not configured to block the shutdown command when Ctrl-Alt-Delete is pressed, this is a finding. 
```

__Fix Text__

```
By default, the system includes the following line in "/etc/init/control-alt-delete.conf" to reboot the system when the Ctrl-Alt-Delete key sequence is pressed:

exec /sbin/shutdown -r now "Ctrl-Alt-Delete pressed"


To configure the system to log a message instead of rebooting the system, add the following line to "/etc/init/control-alt-delete.override" to read as follows:

exec /usr/bin/logger -p security.info "Ctrl-Alt-Delete pressed"
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000287

__Vuln ID__ V-38669

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50470r1_rule

__STIG ID__ RHEL-06-000287

__Rule Title__

`The postfix service must be enabled for mail delivery.`

__Discussion__

```
Local mail delivery is essential to some system maintenance and notification tasks.
```

__Check Content__

```
Run the following command to determine the current status of the "postfix" service:

# service postfix status

If the service is enabled, it should return the following:

postfix is running...

If the service is not enabled, this is a finding.
```

__Fix Text__

```
The Postfix mail transfer agent is used for local mail delivery within the system. The default configuration only listens for connections to the default SMTP port (port 25) on the loopback interface (127.0.0.1). It is recommended to leave this service enabled for local mail delivery. The "postfix" service can be enabled with the following command: 

# chkconfig postfix on
# service postfix start
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000306

__Vuln ID__ V-38670

__Severity__ medium

__Group Title__ SRG-OS-000202

__Rule ID__ SV-50471r2_rule

__STIG ID__ RHEL-06-000306

__Rule Title__

`The operating system must detect unauthorized changes to software and information. `

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-001297
The information system detects unauthorized changes to software and information.
NIST SP 800-53 :: SI-7
NIST SP 800-53A :: SI-7.1


```


### RHEL-06-000288

__Vuln ID__ V-38671

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50472r1_rule

__STIG ID__ RHEL-06-000288

__Rule Title__

`The sendmail package must be removed.`

__Discussion__

```
The sendmail software was not developed with security in mind and its design prevents it from being effectively contained by SELinux. Postfix should be used instead.
```

__Check Content__

```
Run the following command to determine if the "sendmail" package is installed: 

# rpm -q sendmail


If the package is installed, this is a finding.
```

__Fix Text__

```
Sendmail is not the default mail transfer agent and is not installed by default. The "sendmail" package can be removed with the following command: 

# yum erase sendmail
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000289

__Vuln ID__ V-38672

__Severity__ low

__Group Title__ SRG-OS-000096

__Rule ID__ SV-50473r2_rule

__STIG ID__ RHEL-06-000289

__Rule Title__

`The netconsole service must be disabled unless required.`

__Discussion__

```
The "netconsole" service is not necessary unless there is a need to debug kernel panics, which is not common.
```

__Check Content__

```
To check that the "netconsole" service is disabled in system boot configuration, run the following command: 

# chkconfig "netconsole" --list

Output should indicate the "netconsole" service has either not been installed, or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "netconsole" --list
"netconsole" 0:off 1:off 2:off 3:off 4:off 5:off 6:off

Run the following command to verify "netconsole" is disabled through current runtime configuration: 

# service netconsole status

If the service is disabled the command will return the following output: 

netconsole is stopped


If the service is running, this is a finding.
```

__Fix Text__

```
The "netconsole" service is responsible for loading the netconsole kernel module, which logs kernel printk messages over UDP to a syslog server. This allows debugging of problems where disk logging fails and serial consoles are impractical. The "netconsole" service can be disabled with the following commands: 

# chkconfig netconsole off
# service netconsole stop
```

__CCI__

```
CCI-000382
The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (iii)
NIST SP 800-53 Revision 4 :: CM-7 b


```


### RHEL-06-000307

__Vuln ID__ V-38673

__Severity__ medium

__Group Title__ SRG-OS-000265

__Rule ID__ SV-50474r2_rule

__STIG ID__ RHEL-06-000307

__Rule Title__

`The operating system must ensure unauthorized, security-relevant configuration changes detected are tracked.`

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-001589
The organization incorporates detection of unauthorized, security-relevant configuration changes into the organization�s incident response capability to ensure they are tracked.
NIST SP 800-53 :: CM-6 (3)
NIST SP 800-53A :: CM-6 (3).1 (ii)


```


### RHEL-06-000290

__Vuln ID__ V-38674

__Severity__ medium

__Group Title__ SRG-OS-000248

__Rule ID__ SV-50475r1_rule

__STIG ID__ RHEL-06-000290

__Rule Title__

`X Windows must not be enabled unless required.`

__Discussion__

```
Unnecessary services should be disabled to decrease the attack surface of the system.
```

__Check Content__

```
To verify the default runlevel is 3, run the following command: 

# grep initdefault /etc/inittab

The output should show the following: 

id:3:initdefault:


If it does not, this is a finding.
```

__Fix Text__

```
Setting the system's runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in "/etc/inittab" features a "3" as shown: 

id:3:initdefault:
```

__CCI__

```
CCI-001436
The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.
NIST SP 800-53 :: AC-17 (8)
NIST SP 800-53A :: AC-17 (8).1 (ii)


```


### RHEL-06-000308

__Vuln ID__ V-38675

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50476r2_rule

__STIG ID__ RHEL-06-000308

__Rule Title__

`Process core dumps must be disabled unless needed.`

__Discussion__

```
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.
```

__Check Content__

```
To verify that core dumps are disabled for all users, run the following command:

$ grep core /etc/security/limits.conf /etc/security/limits.d/*.conf

The output should be:

* hard core 0

If it is not, this is a finding. 
```

__Fix Text__

```
To disable core dumps for all users, add the following line to "/etc/security/limits.conf": 

* hard core 0
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000291

__Vuln ID__ V-38676

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50477r2_rule

__STIG ID__ RHEL-06-000291

__Rule Title__

`The xorg-x11-server-common (X Windows) package must not be installed, unless required.`

__Discussion__

```
Unnecessary packages should not be installed to decrease the attack surface of the system.
```

__Check Content__

```
To ensure the X Windows package group is removed, run the following command: 

$ rpm -qi xorg-x11-server-common

The output should be: 

package xorg-x11-server-common is not installed


If it is not, this is a finding.
```

__Fix Text__

```
Removing all packages which constitute the X Window System ensures users or malicious software cannot start X. To do so, run the following command: 

# yum groupremove "X Window System"
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000309

__Vuln ID__ V-38677

__Severity__ high

__Group Title__ SRG-OS-000104

__Rule ID__ SV-50478r1_rule

__STIG ID__ RHEL-06-000309

__Rule Title__

`The NFS server must not have the insecure file locking option enabled.`

__Discussion__

```
Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.
```

__Check Content__

```
To verify insecure file locking has been disabled, run the following command: 

# grep insecure_locks /etc/exports


If there is output, this is a finding.
```

__Fix Text__

```
By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files. To get around this, the "insecure_locks" option can be used so these clients can access the desired export. This poses a security risk by potentially allowing the client access to data for which it does not have authorization. Remove any instances of the "insecure_locks" option from the file "/etc/exports".
```

__CCI__

```
CCI-000764
The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).
NIST SP 800-53 :: IA-2
NIST SP 800-53A :: IA-2.1
NIST SP 800-53 Revision 4 :: IA-2


```


### RHEL-06-000311

__Vuln ID__ V-38678

__Severity__ medium

__Group Title__ SRG-OS-000048

__Rule ID__ SV-50479r2_rule

__STIG ID__ RHEL-06-000311

__Rule Title__

`The audit system must provide a warning when allocated audit record storage volume reaches a documented percentage of maximum audit record storage capacity.`

__Discussion__

```
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine whether the system is configured to email the administrator when disk space is starting to run low: 

# grep space_left /etc/audit/auditd.conf 

space_left = [num_megabytes]


If the "num_megabytes" value does not correspond to a documented value for remaining audit partition capacity or if there is no locally documented value for remaining audit partition capacity, this is a finding.
```

__Fix Text__

```
The "auditd" service can be configured to take an action when disk space starts to run low. Edit the file "/etc/audit/auditd.conf". Modify the following line, substituting [num_megabytes] appropriately: 

space_left = [num_megabytes]

The "num_megabytes" value should be set to a fraction of the total audit storage capacity available that will allow a system administrator to be notified with enough time to respond to the situation causing the capacity issues.  This value must also be documented locally.
```

__CCI__

```
CCI-000143
The information system provides a warning when allocated audit record storage volume reaches an organization defined percentage of maximum audit record storage capacity.
NIST SP 800-53 :: AU-5 (1)
NIST SP 800-53A :: AU-5 (1).1 (ii)


```


### RHEL-06-000292

__Vuln ID__ V-38679

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50480r2_rule

__STIG ID__ RHEL-06-000292

__Rule Title__

`The DHCP client must be disabled if not needed.`

__Discussion__

```
DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.
```

__Check Content__

```
To verify that DHCP is not being used, examine the following file for each interface. 

# /etc/sysconfig/network-scripts/ifcfg-[IFACE]

If there is any network interface without a associated "ifcfg" file, this is a finding.

Look for the following:

BOOTPROTO=none

Also verify the following, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]


If it does not, this is a finding.
```

__Fix Text__

```
For each interface [IFACE] on the system (e.g. eth0), edit "/etc/sysconfig/network-scripts/ifcfg-[IFACE]" and make the following changes. 

Correct the BOOTPROTO line to read:

BOOTPROTO=none


Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:

NETMASK=[local LAN netmask]
IPADDR=[assigned IP address]
GATEWAY=[local LAN default gateway]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000313

__Vuln ID__ V-38680

__Severity__ medium

__Group Title__ SRG-OS-000046

__Rule ID__ SV-50481r1_rule

__STIG ID__ RHEL-06-000313

__Rule Title__

`The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.`

__Discussion__

```
Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator: 

action_mail_acct = root


If auditd is not configured to send emails per identified actions, this is a finding.
```

__Fix Text__

```
The "auditd" service can be configured to send email to a designated account in certain situations. Add or correct the following line in "/etc/audit/auditd.conf" to ensure that administrators are notified via email for those situations: 

action_mail_acct = root
```

__CCI__

```
CCI-000139
The information system alerts designated organization-defined personnel or roles in the event of an audit processing failure.
NIST SP 800-53 :: AU-5 a
NIST SP 800-53A :: AU-5.1 (ii)
NIST SP 800-53 Revision 4 :: AU-5 a


```


### RHEL-06-000294

__Vuln ID__ V-38681

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50482r2_rule

__STIG ID__ RHEL-06-000294

__Rule Title__

`All GIDs referenced in /etc/passwd must be defined in /etc/group`

__Discussion__

```
Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.
```

__Check Content__

```
To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command: 

# pwck -r | grep 'no group'

There should be no output. 
If there is output, this is a finding.
```

__Fix Text__

```
Add a group to the system for each GID referenced without a corresponding group.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000315

__Vuln ID__ V-38682

__Severity__ medium

__Group Title__ SRG-OS-000034

__Rule ID__ SV-50483r4_rule

__STIG ID__ RHEL-06-000315

__Rule Title__

`The Bluetooth kernel module must be disabled.`

__Discussion__

```
If Bluetooth functionality must be disabled, preventing the kernel from loading the kernel module provides an additional safeguard against its activation.
```

__Check Content__

```
If the system is configured to prevent the loading of the "bluetooth" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r bluetooth /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.

If the system is configured to prevent the loading of the "net-pf-31" kernel module, it will contain lines inside any file in "/etc/modprobe.d" or the deprecated"/etc/modprobe.conf". These lines instruct the module loading system to run another program (such as "/bin/true") upon a module "install" event. Run the following command to search for such lines in all files in "/etc/modprobe.d" and the deprecated "/etc/modprobe.conf": 

$ grep -r net-pf-31 /etc/modprobe.conf /etc/modprobe.d | grep -i "/bin/true"

If no line is returned, this is a finding.
```

__Fix Text__

```
The kernel's module loading system can be configured to prevent loading of the Bluetooth module. Add the following to the appropriate "/etc/modprobe.d" configuration file to prevent the loading of the Bluetooth module: 

install net-pf-31 /bin/true
install bluetooth /bin/true
```

__CCI__

```
CCI-000085
The organization monitors for unauthorized connections of mobile devices to organizational information systems.
NIST SP 800-53 :: AC-19 c
NIST SP 800-53A :: AC-19.1 (iii)


```


### RHEL-06-000296

__Vuln ID__ V-38683

__Severity__ low

__Group Title__ SRG-OS-000121

__Rule ID__ SV-50484r1_rule

__STIG ID__ RHEL-06-000296

__Rule Title__

`All accounts on the system must have unique user or account names`

__Discussion__

```
Unique usernames allow for accountability on the system.
```

__Check Content__

```
Run the following command to check for duplicate account names: 

# pwck -rq

If there are no duplicate names, no line will be returned. 
If a line is returned, this is a finding.
```

__Fix Text__

```
Change usernames, or delete accounts, so each has a unique name.
```

__CCI__

```
CCI-000804
The information system uniquely identifies and authenticates non-organizational users (or processes acting on behalf of non-organizational users).
NIST SP 800-53 :: IA-8
NIST SP 800-53A :: IA-8.1
NIST SP 800-53 Revision 4 :: IA-8


```


### RHEL-06-000319

__Vuln ID__ V-38684

__Severity__ low

__Group Title__ SRG-OS-000027

__Rule ID__ SV-50485r2_rule

__STIG ID__ RHEL-06-000319

__Rule Title__

`The system must limit users to 10 simultaneous system logins, or a site-defined number, in accordance with operational requirements.`

__Discussion__

```
Limiting simultaneous user logins can insulate the system from denial of service problems caused by excessive logins. Automated login processes operating improperly or maliciously may result in an exceptional number of simultaneous login sessions.
```

__Check Content__

```
Run the following command to ensure the "maxlogins" value is configured for all users on the system:

$ grep "maxlogins" /etc/security/limits.conf /etc/security/limits.d/*.conf

You should receive output similar to the following:

* hard maxlogins 10

If it is not similar, this is a finding. 
```

__Fix Text__

```
Limiting the number of allowed users and sessions per user can limit risks related to denial of service attacks. This addresses concurrent sessions for a single account and does not address concurrent sessions by a single user via multiple accounts. To set the number of concurrent sessions per user add the following line in "/etc/security/limits.conf": 

* hard maxlogins 10

A documented site-defined number may be substituted for 10 in the above.
```

__CCI__

```
CCI-000054
The information system limits the number of concurrent sessions for each organization-defined account and/or account type to an organization-defined number of sessions.
NIST SP 800-53 :: AC-10
NIST SP 800-53A :: AC-10.1 (ii)
NIST SP 800-53 Revision 4 :: AC-10


```


### RHEL-06-000297

__Vuln ID__ V-38685

__Severity__ low

__Group Title__ SRG-OS-000002

__Rule ID__ SV-50486r1_rule

__STIG ID__ RHEL-06-000297

__Rule Title__

`Temporary accounts must be provisioned with an expiration date.`

__Discussion__

```
When temporary accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.
```

__Check Content__

```
For every temporary account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented. 
If any temporary accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
```

__Fix Text__

```
In the event temporary accounts are required, configure the system to terminate them after a documented time period. For every temporary account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

"[YYYY-MM-DD]" indicates the documented expiration date for the account.
```

__CCI__

```
CCI-000016
The information system automatically removes or disables temporary accounts after an organization-defined time period for each type of account.
NIST SP 800-53 :: AC-2 (2)
NIST SP 800-53A :: AC-2 (2).1 (ii)
NIST SP 800-53 Revision 4 :: AC-2 (2)


```


### RHEL-06-000320

__Vuln ID__ V-38686

__Severity__ medium

__Group Title__ SRG-OS-000147

__Rule ID__ SV-50487r1_rule

__STIG ID__ RHEL-06-000320

__Rule Title__

`The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.`

__Discussion__

```
In "iptables" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to "DROP" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
```

__Check Content__

```
Run the following command to ensure the default "FORWARD" policy is "DROP": 

grep ":FORWARD" /etc/sysconfig/iptables

The output must be the following: 

# grep ":FORWARD" /etc/sysconfig/iptables
:FORWARD DROP [0:0]

If it is not, this is a finding.
```

__Fix Text__

```
To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in "/etc/sysconfig/iptables": 

:FORWARD DROP [0:0]
```

__CCI__

```
CCI-001109
The information system at managed interfaces denies network communications traffic by default and allows network communications traffic by exception (i.e., deny all, permit by exception).
NIST SP 800-53 :: SC-7 (5)
NIST SP 800-53A :: SC-7 (5).1 (i) (ii)
NIST SP 800-53 Revision 4 :: SC-7 (5)


```


### RHEL-06-000321

__Vuln ID__ V-38687

__Severity__ low

__Group Title__ SRG-OS-000160

__Rule ID__ SV-50488r3_rule

__STIG ID__ RHEL-06-000321

__Rule Title__

`The system must provide VPN connectivity for communications over untrusted networks.`

__Discussion__

```
Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.
```

__Check Content__

```
If the system does not communicate over untrusted networks, this is not applicable.

Run the following command to determine if the "libreswan" package is installed: 

# rpm -q libreswan

If the package is not installed, this is a finding.
```

__Fix Text__

```
The "libreswan" package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The "libreswan" package can be installed with the following command: 

# yum install libreswan

```

__CCI__

```
CCI-001130
The information system protects the confidentiality of transmitted information.
NIST SP 800-53 :: SC-9
NIST SP 800-53A :: SC-9.1


```


### RHEL-06-000324

__Vuln ID__ V-38688

__Severity__ medium

__Group Title__ SRG-OS-000024

__Rule ID__ SV-50489r3_rule

__STIG ID__ RHEL-06-000324

__Rule Title__

`A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.`

__Discussion__

```
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

To ensure a login warning banner is enabled, run the following: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable

Search for the "banner_message_enable" schema. If properly configured, the "default" value should be "true". 
If it is not, this is a finding.
```

__Fix Text__

```
To enable displaying a login warning banner in the GNOME Display Manager's login screen, run the following command: 

# gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool \
--set /apps/gdm/simple-greeter/banner_message_enable true

To display a banner, this setting must be enabled and then banner text must also be set.
```

__CCI__

```
CCI-000050
The information system retains the notification message or banner on the screen until users acknowledge the usage conditions and take explicit actions to log on to or further access.
NIST SP 800-53 :: AC-8 b
NIST SP 800-53A :: AC-8.1 (iii)
NIST SP 800-53 Revision 4 :: AC-8 b


```


### RHEL-06-000326

__Vuln ID__ V-38689

__Severity__ medium

__Group Title__ SRG-OS-000228

__Rule ID__ SV-50490r5_rule

__STIG ID__ RHEL-06-000326

__Rule Title__

`The Department of Defense (DoD) login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.`

__Discussion__

```
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

To ensure login warning banner text is properly set, run the following: 

$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_text

If properly configured, the proper banner text will appear within this schema. 

The DoD required text is either: 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

OR: 

"I've read & consent to terms in IS user agreem't."

If the DoD required banner text does not appear in the schema, this is a finding.
```

__Fix Text__

```
To set the text shown by the GNOME Display Manager in the login screen, run the following command: 

# gconftool-2
--direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type string \
--set /apps/gdm/simple-greeter/banner_message_text \
"[DoD required text]"

Where the DoD required text is either: 

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: 
-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. 
-At any time, the USG may inspect and seize data stored on this IS. 
-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. 
-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. 
-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." 

OR: 

"I've read & consent to terms in IS user agreem't."

When entering a warning banner that spans several lines, remember to begin and end the string with """. This command writes directly to the file "/etc/gconf/gconf.xml.mandatory/apps/gdm/simple-greeter/%gconf.xml", and this file can later be edited directly if necessary.
```

__CCI__

```
CCI-001384
The information system, for publicly accessible systems, displays system use information organization-defined conditions before granting further access.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (i)
NIST SP 800-53 Revision 4 :: AC-8 c 1

CCI-001385
The information system, for publicly accessible systems, displays references, if any, to monitoring that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001386
The information system for publicly accessible systems displays references, if any, to recording that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001387
The information system for publicly accessible systems displays references, if any, to auditing that are consistent with privacy accommodations for such systems that generally prohibit those activities.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (ii)
NIST SP 800-53 Revision 4 :: AC-8 c 2

CCI-001388
The information system, for publicly accessible systems, includes a description of the authorized uses of the system.
NIST SP 800-53 :: AC-8 c
NIST SP 800-53A :: AC-8.2 (iii)
NIST SP 800-53 Revision 4 :: AC-8 c 3


```


### RHEL-06-000298

__Vuln ID__ V-38690

__Severity__ low

__Group Title__ SRG-OS-000123

__Rule ID__ SV-50491r1_rule

__STIG ID__ RHEL-06-000298

__Rule Title__

`Emergency accounts must be provisioned with an expiration date.
`

__Discussion__

```
When emergency accounts are created, there is a risk they may remain in place and active after the need for them no longer exists. Account expiration greatly reduces the risk of accounts being misused or hijacked.
```

__Check Content__

```
For every emergency account, run the following command to obtain its account aging and expiration information: 

# chage -l [USER]

Verify each of these accounts has an expiration date set as documented. 
If any emergency accounts have no expiration date set or do not expire within a documented time frame, this is a finding.
```

__Fix Text__

```
In the event emergency accounts are required, configure the system to terminate them after a documented time period. For every emergency account, run the following command to set an expiration date on it, substituting "[USER]" and "[YYYY-MM-DD]" appropriately: 

# chage -E [YYYY-MM-DD] [USER]

"[YYYY-MM-DD]" indicates the documented expiration date for the account.
```

__CCI__

```
CCI-001682
The information system automatically removes or disables emergency accounts after an organization-defined time period for each type of account.
NIST SP 800-53 :: AC-2 (2)
NIST SP 800-53A :: AC-2 (2).1 (ii)
NIST SP 800-53 Revision 4 :: AC-2 (2)


```


### RHEL-06-000331

__Vuln ID__ V-38691

__Severity__ medium

__Group Title__ SRG-OS-000034

__Rule ID__ SV-50492r2_rule

__STIG ID__ RHEL-06-000331

__Rule Title__

`The Bluetooth service must be disabled.`

__Discussion__

```
Disabling the "bluetooth" service prevents the system from attempting connections to Bluetooth devices, which entails some security risk. Nevertheless, variation in this risk decision may be expected due to the utility of Bluetooth connectivity and its limited range.
```

__Check Content__

```
To check that the "bluetooth" service is disabled in system boot configuration, run the following command: 

# chkconfig "bluetooth" --list

Output should indicate the "bluetooth" service has either not been installed or has been disabled at all runlevels, as shown in the example below: 

# chkconfig "bluetooth" --list
"bluetooth" 0:off 1:off 2:off 3:off 4:off 5:off 6:off


If the service is configured to run, this is a finding.
```

__Fix Text__

```
The "bluetooth" service can be disabled with the following command: 

# chkconfig bluetooth off



# service bluetooth stop
```

__CCI__

```
CCI-000085
The organization monitors for unauthorized connections of mobile devices to organizational information systems.
NIST SP 800-53 :: AC-19 c
NIST SP 800-53A :: AC-19.1 (iii)


```


### RHEL-06-000334

__Vuln ID__ V-38692

__Severity__ low

__Group Title__ GEN006660

__Rule ID__ SV-50493r1_rule

__STIG ID__ RHEL-06-000334

__Rule Title__

`Accounts must be locked upon 35 days of inactivity.`

__Discussion__

```
Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.
```

__Check Content__

```
To verify the "INACTIVE" setting, run the following command: 

grep "INACTIVE" /etc/default/useradd

The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 

# grep "INACTIVE" /etc/default/useradd
INACTIVE=35

If it does not, this is a finding.
```

__Fix Text__

```
To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 

INACTIVE=[NUM_DAYS]

A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the "useradd" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
```

__CCI__

```
CCI-000017
The information system automatically disables inactive accounts after an organization-defined time period.
NIST SP 800-53 :: AC-2 (3)
NIST SP 800-53A :: AC-2 (3).1 (ii)
NIST SP 800-53 Revision 4 :: AC-2 (3)


```


### RHEL-06-000299

__Vuln ID__ V-38693

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50494r2_rule

__STIG ID__ RHEL-06-000299

__Rule Title__

`The system must require passwords to contain no more than three consecutive repeating characters.`

__Discussion__

```
Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.
```

__Check Content__

```
To check the maximum value for consecutive repeating characters, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth

Look for the value of the "maxrepeat" parameter. The DoD requirement is 3. 
If maxrepeat is not found or not set to the required value, this is a finding.
```

__Fix Text__

```
The pam_cracklib module's "maxrepeat" parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords which contain more than that number of consecutive characters. Add "maxrepeat=3" after pam_cracklib.so to prevent a run of (3 + 1) or more identical characters. 

password required pam_cracklib.so maxrepeat=3 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000335

__Vuln ID__ V-38694

__Severity__ low

__Group Title__ SRG-OS-000118

__Rule ID__ SV-50495r1_rule

__STIG ID__ RHEL-06-000335

__Rule Title__

`The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.`

__Discussion__

```
Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.
```

__Check Content__

```
To verify the "INACTIVE" setting, run the following command: 

grep "INACTIVE" /etc/default/useradd

The output should indicate the "INACTIVE" configuration option is set to an appropriate integer as shown in the example below: 

# grep "INACTIVE" /etc/default/useradd
INACTIVE=35

If it does not, this is a finding.
```

__Fix Text__

```
To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in "/etc/default/useradd", substituting "[NUM_DAYS]" appropriately: 

INACTIVE=[NUM_DAYS]

A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the "useradd" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a "normal" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
```

__CCI__

```
CCI-000795
The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.
NIST SP 800-53 :: IA-4 e
NIST SP 800-53A :: IA-4.1 (iii)
NIST SP 800-53 Revision 4 :: IA-4 e


```


### RHEL-06-000302

__Vuln ID__ V-38695

__Severity__ medium

__Group Title__ SRG-OS-000094

__Rule ID__ SV-50496r2_rule

__STIG ID__ RHEL-06-000302

__Rule Title__

`A file integrity tool must be used at least weekly to check for unauthorized file changes, particularly the addition of unauthorized system libraries or binaries, or for unauthorized modification to authorized system libraries or binaries.`

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output or if aide is not run at least weekly, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-000374
The organization employs automated mechanisms to respond to unauthorized changes to organization defined configuration settings.
NIST SP 800-53 :: CM-6 (2)
NIST SP 800-53A :: CM-6 (2).1 (ii)


```


### RHEL-06-000303

__Vuln ID__ V-38696

__Severity__ medium

__Group Title__ SRG-OS-000098

__Rule ID__ SV-50497r2_rule

__STIG ID__ RHEL-06-000303

__Rule Title__

`The operating system must employ automated mechanisms, per organization defined frequency, to detect the addition of unauthorized components/devices into the operating system.`

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-000416
The organization employs automated mechanisms, per organization defined frequency, to detect the presence of unauthorized hardware, software, and firmware components within the information system.
NIST SP 800-53 :: CM-8 (3) (a)
NIST SP 800-53A :: CM-8 (3).1 (ii)
NIST SP 800-53 Revision 4 :: CM-8 (3) (a)


```


### RHEL-06-000336

__Vuln ID__ V-38697

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50498r2_rule

__STIG ID__ RHEL-06-000336

__Rule Title__

`The sticky bit must be set on all public directories.`

__Discussion__

```
Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure. 

The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, and by users for temporary file storage - such as /tmp - and for directories requiring global read/write access.
```

__Check Content__

```
To find world-writable directories that lack the sticky bit, run the following command for each local partition [PART]: 

# find [PART] -xdev -type d -perm -002 \! -perm -1000


If any world-writable directories are missing the sticky bit, this is a finding.
```

__Fix Text__

```
When the so-called 'sticky bit' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory. Setting the sticky bit prevents users from removing each other's files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit. However, if a directory is used by a particular application, consult that application's documentation instead of blindly changing modes. 
To set the sticky bit on a world-writable directory [DIR], run the following command: 

# chmod +t [DIR]
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000304

__Vuln ID__ V-38698

__Severity__ medium

__Group Title__ SRG-OS-000232

__Rule ID__ SV-50499r2_rule

__STIG ID__ RHEL-06-000304

__Rule Title__

`The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.`

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-001069
The organization employs automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.
NIST SP 800-53 :: RA-5 (7)
NIST SP 800-53A :: RA-5 (7).1 (ii)


```


### RHEL-06-000337

__Vuln ID__ V-38699

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50500r2_rule

__STIG ID__ RHEL-06-000337

__Rule Title__

`All public directories must be owned by a system account.`

__Discussion__

```
Allowing a user account to own a world-writable directory is undesirable because it allows the owner of that directory to remove or replace any files that may be placed in the directory by other users.
```

__Check Content__

```
The following command will discover and print world-writable directories that are not owned by a system account, given the assumption that only system accounts have a uid lower than 500. Run it once for each local partition [PART]: 

# find [PART] -xdev -type d -perm -0002 -uid +499 -print


If there is output, this is a finding.
```

__Fix Text__

```
All directories in local partitions which are world-writable should be owned by root or another system account. If any world-writable directories are not owned by a system account, this should be investigated. Following this, the files should be deleted or assigned to an appropriate group.
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000305

__Vuln ID__ V-38700

__Severity__ medium

__Group Title__ SRG-OS-000196

__Rule ID__ SV-50501r2_rule

__STIG ID__ RHEL-06-000305

__Rule Title__

`The operating system must provide a near real-time alert when any of the organization defined list of compromise or potential compromise indicators occurs. `

__Discussion__

```
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
```

__Check Content__

```
To determine that periodic AIDE execution has been scheduled, run the following command: 

# grep aide /etc/crontab /etc/cron.*/*

If there is no output, this is a finding.
```

__Fix Text__

```
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab: 

05 4 * * * root /usr/sbin/aide --check

AIDE can be executed periodically through other means; this is merely one example.
```

__CCI__

```
CCI-001263
The information system provides near real-time alerts when any of the  organization defined list of compromise or potential compromise indicators occurs.
NIST SP 800-53 :: SI-4 (5)
NIST SP 800-53A :: SI-4 (5).1 (ii)


```


### RHEL-06-000338

__Vuln ID__ V-38701

__Severity__ high

__Group Title__ SRG-OS-999999

__Rule ID__ SV-50502r1_rule

__STIG ID__ RHEL-06-000338

__Rule Title__

`The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.`

__Discussion__

```
Using the "-s" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private.
```

__Check Content__

```
Verify "tftp" is configured by with the "-s" option by running the following command: 

grep "server_args" /etc/xinetd.d/tftp

The output should indicate the "server_args" variable is configured with the "-s" flag, matching the example below:

# grep "server_args" /etc/xinetd.d/tftp
server_args = -s /var/lib/tftpboot

If it does not, this is a finding.
```

__Fix Text__

```
If running the "tftp" service is necessary, it should be configured to change its root directory at startup. To do so, ensure "/etc/xinetd.d/tftp" includes "-s" as a command line argument, as shown in the following example (which is also the default): 

server_args = -s /var/lib/tftpboot
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000339

__Vuln ID__ V-38702

__Severity__ low

__Group Title__ SRG-OS-000037

__Rule ID__ SV-50503r1_rule

__STIG ID__ RHEL-06-000339

__Rule Title__

`The FTP daemon must be configured for logging or verbose mode.`

__Discussion__

```
To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.
```

__Check Content__

```
Find if logging is applied to the ftp daemon. 

Procedures: 

If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file. 

# grep vsftpd /etc/xinetd.d/*



# grep server_args [vsftpd xinetd.d startup file]

This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used. 

# grep xferlog_enable [vsftpd config file]


If xferlog_enable is missing, or is not set to yes, this is a finding.
```

__Fix Text__

```
Add or correct the following configuration options within the "vsftpd" configuration file, located at "/etc/vsftpd/vsftpd.conf". 

xferlog_enable=YES
xferlog_std_format=NO
log_ftp_protocol=YES
```

__CCI__

```
CCI-000130
The information system generates audit records containing information that establishes what type of event occurred.
NIST SP 800-53 :: AU-3
NIST SP 800-53A :: AU-3.1
NIST SP 800-53 Revision 4 :: AU-3


```


### RHEL-06-000527

__Vuln ID__ V-43150

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-55880r2_rule

__STIG ID__ RHEL-06-000527

__Rule Title__

`The login user list must be disabled.`

__Discussion__

```
Leaving the user list enabled is a security risk since it allows anyone with physical access to the system to quickly enumerate known user accounts without logging in.
```

__Check Content__

```
If the GConf2 package is not installed, this is not applicable.

To ensure the user list is disabled, run the following command:

$ gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--get /apps/gdm/simple-greeter/disable_user_list

The output should be "true". If it is not, this is a finding. 
```

__Fix Text__

```
In the default graphical environment, users logging directly into the system are greeted with a login screen that displays all known users. This functionality should be disabled.

Run the following command to disable the user list:

$ sudo gconftool-2 --direct \
--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
--type bool --set /apps/gdm/simple-greeter/disable_user_list true
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000017

__Vuln ID__ V-51337

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-65547r2_rule

__STIG ID__ RHEL-06-000017

__Rule Title__

`The system must use a Linux Security Module at boot time.`

__Discussion__

```
Disabling a major host protection feature, such as SELinux, at boot time prevents it from confining system services at boot time. Further, it increases the chances that it will remain off during system operation.
```

__Check Content__

```
Inspect "/boot/grub/grub.conf" for any instances of "selinux=0" in the kernel boot arguments. Presence of "selinux=0" indicates that SELinux is disabled at boot time. If SELinux is disabled at boot time, this is a finding.
```

__Fix Text__

```
SELinux can be disabled at boot time by an argument in "/boot/grub/grub.conf". Remove any instances of "selinux=0" from the kernel arguments in that file to prevent SELinux from being disabled at boot. 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000020

__Vuln ID__ V-51363

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-65573r1_rule

__STIG ID__ RHEL-06-000020

__Rule Title__

`The system must use a Linux Security Module configured to enforce limits on system services.`

__Discussion__

```
Setting the SELinux state to enforcing ensures SELinux is able to confine potentially compromised processes to the security policy, which is designed to prevent them from causing damage to the system or further elevating their privileges. 
```

__Check Content__

```
Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUX=enforcing

If SELINUX is not set to enforcing, this is a finding. 
```

__Fix Text__

```
The SELinux state should be set to "enforcing" at system boot time. In the file "/etc/selinux/config", add or correct the following line to configure the system to boot into enforcing mode:

SELINUX=enforcing
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000023

__Vuln ID__ V-51369

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-65579r1_rule

__STIG ID__ RHEL-06-000023

__Rule Title__

`The system must use a Linux Security Module configured to limit the privileges of system services.`

__Discussion__

```
Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services. 
```

__Check Content__

```
Check the file "/etc/selinux/config" and ensure the following line appears:

SELINUXTYPE=targeted

If it does not, this is a finding. 
```

__Fix Text__

```
The SELinux "targeted" policy is appropriate for general-purpose desktops and servers, as well as systems in many other roles. To configure the system to use this policy, add or correct the following line in "/etc/selinux/config":

SELINUXTYPE=targeted

Other policies, such as "mls", provide additional security labeling and greater confinement but are not compatible with many general-purpose use cases. 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000025

__Vuln ID__ V-51379

__Severity__ low

__Group Title__ SRG-OS-999999

__Rule ID__ SV-65589r1_rule

__STIG ID__ RHEL-06-000025

__Rule Title__

`All device files must be monitored by the system Linux Security Module.`

__Discussion__

```
If a device file carries the SELinux type "unlabeled_t", then SELinux cannot properly restrict access to the device file. 
```

__Check Content__

```
To check for unlabeled device files, run the following command:

# ls -RZ /dev | grep unlabeled_t

It should produce no output in a well-configured system. 

If there is output, this is a finding. 
```

__Fix Text__

```
Device files, which are used for communication with important system resources, should be labeled with proper SELinux types. If any device files carry the SELinux type "unlabeled_t", investigate the cause and correct the file's context. 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000018

__Vuln ID__ V-51391

__Severity__ medium

__Group Title__ SRG-OS-000232

__Rule ID__ SV-65601r1_rule

__STIG ID__ RHEL-06-000018

__Rule Title__

`A file integrity baseline must be created.`

__Discussion__

```
For AIDE to be effective, an initial database of "known-good" information about files must be captured and it should be able to be verified against the installed files. 
```

__Check Content__

```
To find the location of the AIDE database file, run the following command:

# grep DBDIR /etc/aide.conf

Using the defined values of the [DBDIR] and [database] variables, verify the existence of the AIDE database file:

# ls -l [DBDIR]/[database_file_name]

If there is no database file, this is a finding. 
```

__Fix Text__

```
Run the following command to generate a new database:

# /usr/sbin/aide --init

By default, the database will be written to the file "/var/lib/aide/aide.db.new.gz". Storing the database, the configuration file "/etc/aide.conf", and the binary "/usr/sbin/aide" (or hashes of these files), in a secure location (such as on read-only media) provides additional assurance about their integrity. The newly-generated database can be installed as follows:

# cp /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

To initiate a manual check, run the following command:

# /usr/sbin/aide --check

If this check produces any unexpected output, investigate. 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000372

__Vuln ID__ V-51875

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-66089r1_rule

__STIG ID__ RHEL-06-000372

__Rule Title__

`The operating system, upon successful logon/access, must display to the user the number of unsuccessful logon/access attempts since the last successful logon/access.`

__Discussion__

```
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the number of unsuccessful attempts that were made to login to their account allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators. 
```

__Check Content__

```
To ensure that last logon/access notification is configured correctly, run the following command:

# grep pam_lastlog.so /etc/pam.d/system-auth

The output should show output "showfailed". If that is not the case, this is a finding. 
```

__Fix Text__

```
To configure the system to notify users of last logon/access using "pam_lastlog", add the following line immediately after "session required pam_limits.so":

session required pam_lastlog.so showfailed
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000163

__Vuln ID__ V-54381

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-68627r3_rule

__STIG ID__ RHEL-06-000163

__Rule Title__

`The audit system must switch the system to single-user mode when available audit storage volume becomes dangerously low.`

__Discussion__

```
Administrators should be made aware of an inability to record audit records. If a separate partition or logical volume of adequate size is used, running low on space for audit records should never occur. 
```

__Check Content__

```
Inspect "/etc/audit/auditd.conf" and locate the following line to determine if the system is configured to either suspend, switch to single-user mode, or halt when disk space has run low:

admin_space_left_action = single

If the system is not configured to switch to single-user mode, suspend, or halt for corrective action, this is a finding. 
```

__Fix Text__

```
The "auditd" service can be configured to take an action when disk space is running low but prior to running out of space completely. Edit the file "/etc/audit/auditd.conf". Add or modify the following line, substituting [ACTION] appropriately:

admin_space_left_action = [ACTION]

Set this value to "single" to cause the system to switch to single-user mode for corrective action. Acceptable values also include "suspend" and "halt". For certain systems, the need for availability outweighs the need to log all actions, and a different setting should be determined. Details regarding all possible values for [ACTION] are described in the "auditd.conf" man page. 
```

__CCI__

```
CCI-000366
The organization implements the security configuration settings.
NIST SP 800-53 :: CM-6 b
NIST SP 800-53A :: CM-6.1 (iv)
NIST SP 800-53 Revision 4 :: CM-6 b


```


### RHEL-06-000528

__Vuln ID__ V-57569

__Severity__ medium

__Group Title__ SRG-OS-999999

__Rule ID__ SV-71919r1_rule

__STIG ID__ RHEL-06-000528

__Rule Title__

`The noexec option must be added to the /tmp partition.`

__Discussion__

```
Allowing users to execute binaries from world-writable directories such as "/tmp" should never be necessary in normal operation and can expose the system to potential compromise.
```

__Check Content__

```
To verify that binaries cannot be directly executed from the /tmp directory, run the following command:

$ grep '\s/tmp' /etc/fstab

The resulting output will show whether the /tmp partition has the "noexec" flag set. If the /tmp partition does not have the noexec flag set, this is a finding.
```

__Fix Text__

```
The "noexec" mount option can be used to prevent binaries from being executed out of "/tmp". Add the "noexec" option to the fourth column of "/etc/fstab" for the line which controls mounting of "/tmp".
```

__CCI__

```
CCI-000381
The organization configures the information system to provide only essential capabilities.
NIST SP 800-53 :: CM-7
NIST SP 800-53A :: CM-7.1 (ii)
NIST SP 800-53 Revision 4 :: CM-7 a


```


### RHEL-06-000529

__Vuln ID__ V-58901

__Severity__ medium

__Group Title__ SRG-OS-000373

__Rule ID__ SV-73331r1_rule

__STIG ID__ RHEL-06-000529

__Rule Title__

`The sudo command must require authentication.`

__Discussion__

```
The "sudo" command allows authorized users to run programs (including shells) as other users, system users, and root. The "/etc/sudoers" file is used to configure authorized "sudo" users as well as the programs they are allowed to run. Some configuration options in the "/etc/sudoers" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.
```

__Check Content__

```
Verify neither the "NOPASSWD" option nor the "!authenticate" option is configured for use in "/etc/sudoers" and associated files. Note that the "#include" and "#includedir" directives may be used to include configuration data from locations other than the defaults enumerated here.

# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*
# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*

If the "NOPASSWD" or "!authenticate" options are configured for use in "/etc/sudoers" or associated files, this is a finding.
```

__Fix Text__

```
Update the "/etc/sudoers" or other sudo configuration files to remove or comment out lines utilizing the "NOPASSWD" and "!authenticate" options.

# visudo
# visudo -f [other sudo configuration file]
```

__CCI__

```
CCI-002038
The organization requires users to reauthenticate when organization-defined circumstances or situations requiring reauthentication.
NIST SP 800-53 Revision 4 :: IA-11


```


### RHEL-06-000293

__Vuln ID__ V-72817

__Severity__ medium

__Group Title__ RHEL-06-000293

__Rule ID__ SV-87461r1_rule

__STIG ID__ RHEL-06-000293

__Rule Title__

`Wireless network adapters must be disabled.`

__Discussion__

```
The use of wireless networking can introduce many different attack vectors into the organization�s network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.
```

__Check Content__

```
This is N/A for systems that do not have wireless network adapters.

Verify that there are no wireless interfaces configured on the system:

# ifconfig -a


eth0      Link encap:Ethernet  HWaddr b8:ac:6f:65:31:e5  
          inet addr:192.168.2.100  Bcast:192.168.2.255  Mask:255.255.255.0
          inet6 addr: fe80::baac:6fff:fe65:31e5/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:2697529 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2630541 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:2159382827 (2.0 GiB)  TX bytes:1389552776 (1.2 GiB)
          Interrupt:17 

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:16436  Metric:1
          RX packets:2849 errors:0 dropped:0 overruns:0 frame:0
          TX packets:2849 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:2778290 (2.6 MiB)  TX bytes:2778290 (2.6 MiB)


If a wireless interface is configured, it must be documented and approved by the local Authorizing Official.

If a wireless interface is configured and has not been documented and approved, this is a finding.

```

__Fix Text__

```
Configure the system to disable all wireless network interfaces.
```

__CCI__

```
CCI-001443
The information system protects wireless access to the system using authentication of users and/or devices.
NIST SP 800-53 :: AC-18 (1)
NIST SP 800-53A :: AC-18 (1).1
NIST SP 800-53 Revision 4 :: AC-18 (1)

CCI-001444
The information system protects wireless access to the system using encryption.
NIST SP 800-53 :: AC-18 (1)
NIST SP 800-53A :: AC-18 (1).1
NIST SP 800-53 Revision 4 :: AC-18 (1)

CCI-002418
The information system protects the confidentiality and/or integrity of transmitted information.
NIST SP 800-53 Revision 4 :: SC-8


```

