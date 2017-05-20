# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010490
#
# VULN ID
#   V-71963
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000080-GPOS-00048
#
# RULE ID
#   SV-86587r1_rule
#
# STIG ID
#   RHEL-07-010490
#
# RULE TITLE
#   Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010490;

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
    return 'V-71963';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000080-GPOS-00048';
}

sub get_rule_id {
    return 'SV-86587r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010490';
}

sub get_rule_title {
    return
        'Systems using Unified Extensible Firmware Interface (UEFI) must require authentication upon booting into single-user and maintenance modes.';
}

sub get_discussion {
    return <<'DISCUSSION';
If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system. GRUB 2 is the default boot loader for RHEL 7 and is designed to require a password to boot into single-user mode or make modifications to the boot menu.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check to see if an encrypted root password is set. On systems that use UEFI, use the following command:



# grep -i password /boot/efi/EFI/redhat/grub.cfg

password_pbkdf2 superusers-account password-hash



If the root password entry does not begin with ""password_pbkdf2"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system to encrypt the boot password for root.



Generate an encrypted grub2 password for root with the following command:



Note: The hash generated is an example.



# grub-mkpasswd-pbkdf2

Enter Password:

Reenter Password:



PBKDF2 hash of your password is grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45



Using this hash, modify the ""/etc/grub.d/10_linux"" file with the following commands to add the password to the root entry:



# cat << EOF

> set superusers=""root"" password_pbkdf2 smithj grub.pbkdf2.sha512.10000.F3A7CFAA5A51EED123BE8238C23B25B2A6909AFC9812F0D45

> EOF



Generate a new ""grub.conf"" file with the new password with the following commands:



# grub2-mkconfig --output=/tmp/grub2.cfg

# mv /tmp/grub2.cfg /boot/efi/EFI/redhat/grub.cfg
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000213

The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

NIST SP 800-53 :: AC-3

NIST SP 800-53A :: AC-3.1

NIST SP 800-53 Revision 4 :: AC-3




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
