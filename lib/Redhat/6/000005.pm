# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000005
#
# VULN ID
#   V-38470
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000045
#
# RULE ID
#   SV-50270r2_rule
#
# STIG ID
#   RHEL-06-000005
#
# RULE TITLE
#   The audit system must alert designated staff members when the audit storage volume approaches capacity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000005;

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
    $self->{VULN_ID} = 'V-38470';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000045';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50270r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000005';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must alert designated staff members when the audit storage volume approaches capacity.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low:



# grep space_left_action /etc/audit/auditd.conf

space_left_action = email





If the system is not configured to send an email to the system administrator when disk space is starting to run low, this is a finding.  The ""syslog"" option is acceptable when it can be demonstrated that the local log management infrastructure notifies an appropriate administrator in a timely manner.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""auditd"" service can be configured to take an action when disk space starts to run low. Edit the file ""/etc/audit/auditd.conf"". Modify the following line, substituting [ACTION] appropriately:



space_left_action = [ACTION]



Possible values for [ACTION] are described in the ""auditd.conf"" man page. These include:



""ignore""

""syslog""

""email""

""exec""

""suspend""

""single""

""halt""





Set this to ""email"" (instead of the default, which is ""suspend"") as it is more likely to get prompt attention.  The ""syslog"" option is acceptable, provided the local log management infrastructure notifies an appropriate administrator in a timely manner.



RHEL-06-000521 ensures that the email generated through the operation ""space_left_action"" will be sent to an administrator.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000138

The organization configures auditing to reduce the likelihood of storage capacity being exceeded.

NIST SP 800-53 :: AU-4

NIST SP 800-53A :: AU-4.1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
