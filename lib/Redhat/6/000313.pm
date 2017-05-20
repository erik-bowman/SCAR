# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000313
#
# VULN ID
#   V-38680
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000046
#
# RULE ID
#   SV-50481r1_rule
#
# STIG ID
#   RHEL-06-000313
#
# RULE TITLE
#   The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000313;

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
    return 'V-38680';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000046';
}

sub get_rule_id {
    return 'SV-50481r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000313';
}

sub get_rule_title {
    return
        'The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.';
}

sub get_discussion {
    return <<'DISCUSSION';
Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator:



action_mail_acct = root





If auditd is not configured to send emails per identified actions, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""auditd"" service can be configured to send email to a designated account in certain situations. Add or correct the following line in ""/etc/audit/auditd.conf"" to ensure that administrators are notified via email for those situations:



action_mail_acct = root
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000139

The information system alerts designated organization-defined personnel or roles in the event of an audit processing failure.

NIST SP 800-53 :: AU-5 a

NIST SP 800-53A :: AU-5.1 (ii)

NIST SP 800-53 Revision 4 :: AU-5 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
