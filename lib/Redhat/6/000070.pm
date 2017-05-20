# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000070
#
# VULN ID
#   V-38588
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000080
#
# RULE ID
#   SV-50389r1_rule
#
# STIG ID
#   RHEL-06-000070
#
# RULE TITLE
#   The system must not permit interactive boot.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000070;

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
    return 'V-38588';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000080';
}

sub get_rule_id {
    return 'SV-50389r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000070';
}

sub get_rule_title {
    return 'The system must not permit interactive boot.';
}

sub get_discussion {
    return <<'DISCUSSION';
Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check whether interactive boot is disabled, run the following command:



$ grep PROMPT /etc/sysconfig/init



If interactive boot is disabled, the output will show:



PROMPT=no





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To disable the ability for users to perform interactive startups, edit the file ""/etc/sysconfig/init"". Add or correct the line:



PROMPT=no



The ""PROMPT"" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.
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
