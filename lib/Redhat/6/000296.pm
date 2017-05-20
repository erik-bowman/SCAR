# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000296
#
# VULN ID
#   V-38683
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000121
#
# RULE ID
#   SV-50484r1_rule
#
# STIG ID
#   RHEL-06-000296
#
# RULE TITLE
#   All accounts on the system must have unique user or account names
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000296;

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
    return 'V-38683';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000121';
}

sub get_rule_id {
    return 'SV-50484r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000296';
}

sub get_rule_title {
    return
        'All accounts on the system must have unique user or account names';
}

sub get_discussion {
    return <<'DISCUSSION';
Unique usernames allow for accountability on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to check for duplicate account names:



# pwck -rq



If there are no duplicate names, no line will be returned.

If a line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change usernames, or delete accounts, so each has a unique name.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000804

The information system uniquely identifies and authenticates non-organizational users (or processes acting on behalf of non-organizational users).

NIST SP 800-53 :: IA-8

NIST SP 800-53A :: IA-8.1

NIST SP 800-53 Revision 4 :: IA-8




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
