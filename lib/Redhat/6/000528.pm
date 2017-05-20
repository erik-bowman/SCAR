# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000528
#
# VULN ID
#   V-57569
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-71919r1_rule
#
# STIG ID
#   RHEL-06-000528
#
# RULE TITLE
#   The noexec option must be added to the /tmp partition.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000528;

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
    return 'V-57569';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-71919r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000528';
}

sub get_rule_title {
    return 'The noexec option must be added to the /tmp partition.';
}

sub get_discussion {
    return <<'DISCUSSION';
Allowing users to execute binaries from world-writable directories such as ""/tmp"" should never be necessary in normal operation and can expose the system to potential compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that binaries cannot be directly executed from the /tmp directory, run the following command:



$ grep '\s/tmp' /etc/fstab



The resulting output will show whether the /tmp partition has the ""noexec"" flag set. If the /tmp partition does not have the noexec flag set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""noexec"" mount option can be used to prevent binaries from being executed out of ""/tmp"". Add the ""noexec"" option to the fourth column of ""/etc/fstab"" for the line which controls mounting of ""/tmp"".
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000381

The organization configures the information system to provide only essential capabilities.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (ii)

NIST SP 800-53 Revision 4 :: CM-7 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
