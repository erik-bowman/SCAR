# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040000
#
# VULN ID
#   V-72217
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000027-GPOS-00008
#
# RULE ID
#   SV-86841r1_rule
#
# STIG ID
#   RHEL-07-040000
#
# RULE TITLE
#   The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040000;

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
    return 'V-72217';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000027-GPOS-00008';
}

sub get_rule_id {
    return 'SV-86841r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040000';
}

sub get_rule_title {
    return
        'The operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types.';
}

sub get_discussion {
    return <<'DISCUSSION';
Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.



This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system limits the number of concurrent sessions to ""10"" for all accounts and/or account types by issuing the following command:



# grep ""maxlogins"" /etc/security/limits.conf

* hard maxlogins 10



This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains.



If the ""maxlogins"" item is missing or the value is not set to ""10"" or less for all domains that have the ""maxlogins"" item assigned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to limit the number of concurrent sessions to ""10"" for all accounts and/or account types.



Add the following line to the top of the /etc/security/limits.conf:



* hard maxlogins 10
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000054

The information system limits the number of concurrent sessions for each organization-defined account and/or account type to an organization-defined number of sessions.

NIST SP 800-53 :: AC-10

NIST SP 800-53A :: AC-10.1 (ii)

NIST SP 800-53 Revision 4 :: AC-10




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
