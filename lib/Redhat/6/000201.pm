# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000201
#
# VULN ID
#   V-38578
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50379r2_rule
#
# STIG ID
#   RHEL-06-000201
#
# RULE TITLE
#   The audit system must be configured to audit changes to the /etc/sudoers file.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000201;

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
    return 'V-38578';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000064';
}

sub get_rule_id {
    return 'SV-50379r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000201';
}

sub get_rule_title {
    return
        'The audit system must be configured to audit changes to the /etc/sudoers file.';
}

sub get_discussion {
    return <<'DISCUSSION';
The actions taken by system administrators should be audited to keep a record of what was executed on the system, as well as, for accountability purposes.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that auditing is configured for system administrator actions, run the following command:



$ sudo grep -w ""/etc/sudoers"" /etc/audit/audit.rules



If the system is configured to watch for changes to its sudoers configuration, a line should be returned (including ""-p wa"" indicating permissions that are watched).



If there is no output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
At a minimum, the audit system should collect administrator actions for all users and root. Add the following to ""/etc/audit/audit.rules"":



-w /etc/sudoers -p wa -k actions
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
