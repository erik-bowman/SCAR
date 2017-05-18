#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030320
#
# VULN ID
#   V-72087
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-86711r2_rule
#
# STIG ID
#   RHEL-07-030320
#
# RULE TITLE
#   The audit system must take appropriate action when the audit storage volume is full.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030320;

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
    $self->{VULN_ID} = 'V-72087';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000342-GPOS-00133';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86711r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030320';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must take appropriate action when the audit storage volume is full.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Taking appropriate action in case of a filled audit storage volume will minimize the possibility of losing audit records.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the action the operating system takes if the disk the audit records are written to becomes full.



To determine the action that takes place if the disk is full on the remote server, use the following command:



# grep -i disk_full_action /etc/audisp/audisp-remote.conf

disk_full_action = single



To determine the action that takes place if the network connection fails, use the following command:



# grep -i network_failure_action /etc/audisp/audisp-remote.conf

network_failure_action = stop



If the value of the ""network_failure_action"" option is not ""syslog"", ""single"", or ""halt"", or the line is commented out, this is a finding.



If the value of the ""disk_full_action"" option is not ""syslog"", ""single"", or ""halt"", or the line is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the action the operating system takes if the disk the audit records are written to becomes full.



Uncomment or edit the ""disk_full_action"" option in ""/etc/audisp/audisp-remote.conf"" and set it to ""syslog"", ""single"", or ""halt"", such as the following line:



disk_full_action = single



Uncomment the ""network_failure_action"" option in ""/etc/audisp/audisp-remote.conf"" and set it to ""syslog"", ""single"", or ""halt"".
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
