# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000183
#
# VULN ID
#   V-38541
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50342r2_rule
#
# STIG ID
#   RHEL-06-000183
#
# RULE TITLE
#   The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000183;

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
    return 'V-38541';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50342r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000183';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit modifications to the systems Mandatory Access Control (MAC) configuration (SELinux).';
}

sub get_discussion {
    return <<'DISCUSSION';
The system's mandatory access policy (SELinux) should not be arbitrarily changed by anything other than administrator action. All changes to MAC policy should be audited.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine if the system is configured to audit changes to its SELinux configuration files, run the following command:



$ sudo grep -w ""/etc/selinux"" /etc/audit/audit.rules



If the system is configured to watch for changes to its SELinux configuration, a line should be returned (including ""-p wa"" indicating permissions that are watched).



If the system is not configured to audit attempts to change the MAC policy, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"":



-w /etc/selinux/ -p wa -k MAC-policy
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
