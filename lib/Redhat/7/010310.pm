# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010310
#
# VULN ID
#   V-71941
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000118-GPOS-00060
#
# RULE ID
#   SV-86565r1_rule
#
# STIG ID
#   RHEL-07-010310
#
# RULE TITLE
#   The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010310;

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
    return 'V-71941';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000118-GPOS-00060';
}

sub get_rule_id {
    return 'SV-86565r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010310';
}

sub get_rule_title {
    return
        'The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.';
}

sub get_discussion {
    return <<'DISCUSSION';
Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.



Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:



# grep -i inactive /etc/default/useradd

INACTIVE=0



If the value is not set to ""0"", is commented out, or is not defined, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after the password expires.



Add the following line to ""/etc/default/useradd"" (or modify the line to have the required value):



INACTIVE=0
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000795

The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.

NIST SP 800-53 :: IA-4 e

NIST SP 800-53A :: IA-4.1 (iii)

NIST SP 800-53 Revision 4 :: IA-4 e




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
