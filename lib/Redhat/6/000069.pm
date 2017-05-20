# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000069
#
# VULN ID
#   V-38586
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000080
#
# RULE ID
#   SV-50387r1_rule
#
# STIG ID
#   RHEL-06-000069
#
# RULE TITLE
#   The system must require authentication upon booting into single-user and maintenance modes.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000069;

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
    return 'V-38586';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000080';
}

sub get_rule_id {
    return 'SV-50387r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000069';
}

sub get_rule_title {
    return
        'The system must require authentication upon booting into single-user and maintenance modes.';
}

sub get_discussion {
    return <<'DISCUSSION';
This prevents attackers with physical access from trivially bypassing security on the machine and gaining root access. Such accesses are further prevented by configuring the bootloader password.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check if authentication is required for single-user mode, run the following command:



$ grep SINGLE /etc/sysconfig/init



The output should be the following:



SINGLE=/sbin/sulogin





If the output is different, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Single-user mode is intended as a system recovery method, providing a single user root access to the system by providing a boot option at startup. By default, no authentication is performed if single-user mode is selected.



To require entry of the root password even if the system is started in single-user mode, add or correct the following line in the file ""/etc/sysconfig/init"":



SINGLE=/sbin/sulogin
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
