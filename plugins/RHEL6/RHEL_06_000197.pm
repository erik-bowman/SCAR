#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000197
#
# VULN ID
#   V-38566
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000064
#
# RULE ID
#   SV-50367r2_rule
#
# STIG ID
#   RHEL-06-000197
#
# RULE TITLE
#   The audit system must be configured to audit failed attempts to access files and programs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000197;

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
    $self->{VULN_ID} = 'V-38566';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000064';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50367r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000197';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must be configured to audit failed attempts to access files and programs.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Unsuccessful attempts to access files could be an indicator of malicious activity on a system. Auditing these events could serve as evidence of potential system compromise.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To verify that the audit system collects unauthorized file accesses, run the following commands:



# grep EACCES /etc/audit/audit.rules







# grep EPERM /etc/audit/audit.rules





If either command lacks output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
At a minimum, the audit system should collect unauthorized file accesses for all users and root. Add the following to ""/etc/audit/audit.rules"", setting ARCH to either b32 or b64 as appropriate for your system:



-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EACCES -F auid=0 -k access

-a always,exit -F arch=ARCH -S creat -S open -S openat -S truncate \

-S ftruncate -F exit=-EPERM -F auid=0 -k access
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
