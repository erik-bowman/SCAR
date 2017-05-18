#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000070
#
# VULN ID
#   V-38588
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000080
#
# RULE ID
#   SV-50389r1_rule
#
# STIG ID
#   RHEL-06-000070
#
# RULE TITLE
#   The system must not permit interactive boot.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000070;

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
    $self->{VULN_ID} = 'V-38588';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000080';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50389r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000070';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The system must not permit interactive boot.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Using interactive boot, the console user could disable auditing, firewalls, or other services, weakening system security.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check whether interactive boot is disabled, run the following command:



$ grep PROMPT /etc/sysconfig/init



If interactive boot is disabled, the output will show:



PROMPT=no





If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To disable the ability for users to perform interactive startups, edit the file ""/etc/sysconfig/init"". Add or correct the line:



PROMPT=no



The ""PROMPT"" option allows the console user to perform an interactive system startup, in which it is possible to select the set of services which are started on boot.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000213

The information system enforces approved authorizations for logical access to information and system resources in accordance with applicable access control policies.

NIST SP 800-53 :: AC-3

NIST SP 800-53A :: AC-3.1

NIST SP 800-53 Revision 4 :: AC-3




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
