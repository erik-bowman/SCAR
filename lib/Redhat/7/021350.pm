# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021350
#
# VULN ID
#   V-72067
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000033-GPOS-00014
#
# RULE ID
#   SV-86691r2_rule
#
# STIG ID
#   RHEL-07-021350
#
# RULE TITLE
#   The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021350;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

# Plugin version
our $VERSION = 0.01;

sub new {
    my ( $class, $parent ) = @_;
    my $self = bless { parent => $parent }, $class;

    return $self;
}

sub check {
    my ($self) = @_;

    return $self;
}

sub remediate {
    my ($self) = @_;

    return $self;
}

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-72067';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000033-GPOS-00014';
}

sub get_rule_id {
    return 'SV-86691r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-021350';
}

sub get_rule_title {
    return
        'The operating system must implement NIST FIPS-validated cryptography for the following: to provision digital signatures, to generate cryptographic hashes, and to protect data requiring data-at-rest protections in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.';
}

sub get_discussion {
    return <<'DISCUSSION';
Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.



Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000185-GPOS-00079, SRG-OS-000396-GPOS-00176, SRG-OS-000405-GPOS-00184, SRG-OS-000478-GPOS-00223
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system implements DoD-approved encryption to protect the confidentiality of remote access sessions.



Check to see if the ""dracut-fips"" package is installed with the following command:



# yum list installed | grep dracut-fips



dracut-fips-033-360.el7_2.x86_64.rpm



If a ""dracut-fips"" package is installed, check to see if the kernel command line is configured to use FIPS mode with the following command:



Note: GRUB 2 reads its configuration from the ""/boot/grub2/grub.cfg"" file on traditional BIOS-based machines and from the ""/boot/efi/EFI/redhat/grub.cfg"" file on UEFI machines.



# grep fips /boot/grub2/grub.cfg

/vmlinuz-3.8.0-0.40.el7.x86_64 root=/dev/mapper/rhel-root ro rd.md=0 rd.dm=0 rd.lvm.lv=rhel/swap crashkernel=auto rd.luks=0 vconsole.keymap=us rd.lvm.lv=rhel/root rhgb fips=1 quiet



If the kernel command line is configured to use FIPS mode, check to see if the system is in FIPS mode with the following command:



# cat /proc/sys/crypto/fips_enabled

1



If a ""dracut-fips"" package is not installed, the kernel command line does not have a fips entry, or the system has a value of ""0"" for ""fips_enabled"" in ""/proc/sys/crypto"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to implement DoD-approved encryption by installing the dracut-fips package.



To enable strict FIPS compliance, the fips=1 kernel option needs to be added to the kernel command line during system installation so key generation is done with FIPS-approved algorithms and continuous monitoring tests in place.



Configure the operating system to implement DoD-approved encryption by following the steps below:



The fips=1 kernel option needs to be added to the kernel command line during system installation so that key generation is done with FIPS-approved algorithms and continuous monitoring tests in place. Users should also ensure that the system has plenty of entropy during the installation process by moving the mouse around, or if no mouse is available, ensuring that many keystrokes are typed. The recommended amount of keystrokes is 256 and more. Less than 256 keystrokes may generate a non-unique key.



For proper operation of the in-module integrity verification, the prelink has to be disabled. This can be done by configuring PRELINKING=no in the ""/etc/sysconfig/prelink"" configuration file. Existing prelinking, if any, should be undone on all system files using the prelink -u -a command.



Install the dracut-fips package with the following command:



# yum install dracut-fips



Recreate the ""initramfs"" file with the following command:



Note: This command will overwrite the existing ""initramfs"" file.



# dracut -f



Modify the kernel command line of the current kernel in the ""grub.cfg"" file by adding the following option to the GRUB_CMDLINE_LINUX key in the ""/etc/default/grub"" file and then rebuild the ""grub.cfg"" file:



fips=1



Changes to ""/etc/default/grub"" require rebuilding the ""grub.cfg"" file as follows:



On BIOS-based machines, use the following command:



# grub2-mkconfig -o /boot/grub2/grub.cfg



On UEFI-based machines, use the following command:



# grub2-mkconfig -o /boot/efi/EFI/redhat/grub.cfg



If /boot or /boot/efi reside on separate partitions, the kernel parameter boot=<partition of /boot or /boot/efi> must be added to the kernel command line. You can identify a partition by running the df /boot or df /boot/efi command:



# df /boot

Filesystem           1K-blocks      Used Available Use% Mounted on

/dev/sda1               495844     53780    416464  12% /boot



To ensure the boot= configuration option will work even if device naming changes between boots, identify the universally unique identifier (UUID) of the partition with the following command:



# blkid /dev/sda1

/dev/sda1: UUID=""05c000f1-a213-759e-c7a2-f11b7424c797"" TYPE=""ext4""



For the example above, append the following string to the kernel command line:



boot=UUID=05c000f1-a213-759e-c7a2-f11b7424c797



Reboot the system for the changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000068

The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)



CCI-001199

The information system protects the confidentiality and/or integrity of organization-defined information at rest.

NIST SP 800-53 :: SC-28

NIST SP 800-53A :: SC-28.1

NIST SP 800-53 Revision 4 :: SC-28



CCI-002450

The information system implements organization-defined cryptographic uses and type of cryptography required for each use in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

NIST SP 800-53 Revision 4 :: SC-13



CCI-002476

The information system implements cryptographic mechanisms to prevent unauthorized disclosure of organization-defined information at rest on organization-defined information system components.

NIST SP 800-53 Revision 4 :: SC-28 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__