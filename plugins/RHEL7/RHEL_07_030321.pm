#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030321
#
# VULN ID
#   V-73163
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-87815r2_rule
#
# STIG ID
#   RHEL-07-030321
#
# RULE TITLE
#   The audit system must take appropriate action when there is an error sending audit records to a remote system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030321;

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
    $self->{VULN_ID} = 'V-73163';
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
    $self->{RULE_ID} = 'SV-87815r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030321';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must take appropriate action when there is an error sending audit records to a remote system.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Taking appropriate action when there is an error sending audit records to a remote system will minimize the possibility of losing audit records.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the action the operating system takes if there is an error sending audit records to a remote system.



Check the action that takes place if there is an error sending audit records to a remote system with the following command:



# grep -i network_failure_action /etc/audisp/audisp-remote.conf

network_failure_action = stop



If the value of the ""network_failure_action"" option is not ""syslog"", ""single"", or ""halt"", or the line is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the action the operating system takes if there is an error sending audit records to a remote system.



Uncomment the ""network_failure_action"" option in ""/etc/audisp/audisp-remote.conf"" and set it to ""syslog"", ""single"", or ""halt"".



network_failure_action = single
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
