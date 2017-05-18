#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000511
#
# VULN ID
#   V-38464
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000047
#
# RULE ID
#   SV-50264r1_rule
#
# STIG ID
#   RHEL-06-000511
#
# RULE TITLE
#   The audit system must take appropriate action when there are disk errors on the audit storage volume.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000511;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-38464';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000047';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50264r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000511';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must take appropriate action when there are disk errors on the audit storage volume.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Taking appropriate action in case of disk errors will minimize the possibility of losing audit records.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to take appropriate action when disk errors occur:



# grep disk_error_action /etc/audit/auditd.conf

disk_error_action = [ACTION]





If the system is configured to ""suspend"" when disk errors occur or ""ignore"" them, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Edit the file ""/etc/audit/auditd.conf"". Modify the following line, substituting [ACTION] appropriately:



disk_error_action = [ACTION]



Possible values for [ACTION] are described in the ""auditd.conf"" man page. These include:



""ignore""

""syslog""

""exec""

""suspend""

""single""

""halt""





Set this to ""syslog"", ""exec"", ""single"", or ""halt"".
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000140

The information system takes organization-defined actions upon audit failure (e.g., shut down information system, overwrite oldest audit records, stop generating audit records).

NIST SP 800-53 :: AU-5 b

NIST SP 800-53A :: AU-5.1 (iv)

NIST SP 800-53 Revision 4 :: AU-5 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
