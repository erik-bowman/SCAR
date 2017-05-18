#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010310
#
# VULN ID
#   V-71941
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000118-GPOS-00060
#
# RULE ID
#   SV-86565r1_rule
#
# STIG ID
#   RHEL-07-010310
#
# RULE TITLE
#   The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010310;

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
    $self->{VULN_ID} = 'V-71941';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000118-GPOS-00060';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86565r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010310';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must disable account identifiers (individuals, groups, roles, and devices) if the password expires.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Inactive identifiers pose a risk to systems and applications because attackers may exploit an inactive identifier and potentially obtain undetected access to the system. Owners of inactive accounts will not notice if unauthorized access to their user account has been obtained.



Operating systems need to track periods of inactivity and disable application identifiers after zero days of inactivity.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system disables account identifiers (individuals, groups, roles, and devices) after the password expires with the following command:



# grep -i inactive /etc/default/useradd

INACTIVE=0



If the value is not set to ""0"", is commented out, or is not defined, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to disable account identifiers (individuals, groups, roles, and devices) after the password expires.



Add the following line to ""/etc/default/useradd"" (or modify the line to have the required value):



INACTIVE=0
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000795

The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.

NIST SP 800-53 :: IA-4 e

NIST SP 800-53A :: IA-4.1 (iii)

NIST SP 800-53 Revision 4 :: IA-4 e




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
