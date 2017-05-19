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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38680';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000046';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50481r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000313';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must identify staff members to receive notifications of audit log storage volume capacity issues.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Email sent to the root account is typically aliased to the administrators of the system, who can take appropriate action.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to send email to an account when it needs to notify an administrator:



action_mail_acct = root





If auditd is not configured to send emails per identified actions, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""auditd"" service can be configured to send email to a designated account in certain situations. Add or correct the following line in ""/etc/audit/auditd.conf"" to ensure that administrators are notified via email for those situations:



action_mail_acct = root
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000139

The information system alerts designated organization-defined personnel or roles in the event of an audit processing failure.

NIST SP 800-53 :: AU-5 a

NIST SP 800-53A :: AU-5.1 (ii)

NIST SP 800-53 Revision 4 :: AU-5 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
