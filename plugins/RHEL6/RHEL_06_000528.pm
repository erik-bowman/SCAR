#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000528
#
# VULN ID
#   V-57569
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-71919r1_rule
#
# STIG ID
#   RHEL-06-000528
#
# RULE TITLE
#   The noexec option must be added to the /tmp partition.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000528;

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
    $self->{VULN_ID} = 'V-57569';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-71919r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000528';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The noexec option must be added to the /tmp partition.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Allowing users to execute binaries from world-writable directories such as ""/tmp"" should never be necessary in normal operation and can expose the system to potential compromise.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To verify that binaries cannot be directly executed from the /tmp directory, run the following command:



$ grep '\s/tmp' /etc/fstab



The resulting output will show whether the /tmp partition has the ""noexec"" flag set. If the /tmp partition does not have the noexec flag set, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""noexec"" mount option can be used to prevent binaries from being executed out of ""/tmp"". Add the ""noexec"" option to the fourth column of ""/etc/fstab"" for the line which controls mounting of ""/tmp"".
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000381

The organization configures the information system to provide only essential capabilities.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (ii)

NIST SP 800-53 Revision 4 :: CM-7 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
