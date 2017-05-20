# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000068
#
# VULN ID
#   V-38585
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000080
#
# RULE ID
#   SV-50386r3_rule
#
# STIG ID
#   RHEL-06-000068
#
# RULE TITLE
#   The system boot loader must require authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000068;

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
    return 'V-38585';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000080';
}

sub get_rule_id {
    return 'SV-50386r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000068';
}

sub get_rule_title {
    return 'The system boot loader must require authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
Password protection on the boot loader configuration ensures users with physical access cannot trivially alter important bootloader settings. These include which kernel to use, and whether to enter single-user mode.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the boot loader password has been set and encrypted, run the following command:



# grep password /boot/grub/grub.conf



The output should show the following:



password --encrypted $6$[rest-of-the-password-hash]



If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The grub boot loader should have password protection enabled to protect boot-time settings. To do so, select a password and then generate a hash from it by running the following command:



# grub-crypt --sha-512



When prompted to enter a password, insert the following line into ""/boot/grub/grub.conf"" immediately after the header comments. (Use the output from ""grub-crypt"" as the value of [password-hash]):



password --encrypted [password-hash]
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
