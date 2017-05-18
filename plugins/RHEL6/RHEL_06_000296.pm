#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000296
#
# VULN ID
#   V-38683
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000121
#
# RULE ID
#   SV-50484r1_rule
#
# STIG ID
#   RHEL-06-000296
#
# RULE TITLE
#   All accounts on the system must have unique user or account names
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000296;

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
    $self->{VULN_ID} = 'V-38683';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000121';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50484r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000296';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All accounts on the system must have unique user or account names';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Unique usernames allow for accountability on the system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to check for duplicate account names:



# pwck -rq



If there are no duplicate names, no line will be returned.

If a line is returned, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Change usernames, or delete accounts, so each has a unique name.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000804

The information system uniquely identifies and authenticates non-organizational users (or processes acting on behalf of non-organizational users).

NIST SP 800-53 :: IA-8

NIST SP 800-53A :: IA-8.1

NIST SP 800-53 Revision 4 :: IA-8




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
