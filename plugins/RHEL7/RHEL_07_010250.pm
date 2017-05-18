#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010250
#
# VULN ID
#   V-71929
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000076-GPOS-00044
#
# RULE ID
#   SV-86553r1_rule
#
# STIG ID
#   RHEL-07-010250
#
# RULE TITLE
#   Passwords for new users must be restricted to a 60-day maximum lifetime.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010250;

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
    $self->{VULN_ID} = 'V-71929';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000076-GPOS-00044';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86553r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010250';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Passwords for new users must be restricted to a 60-day maximum lifetime.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system enforces a 60-day maximum password lifetime restriction for new user accounts.



Check for the value of ""PASS_MAX_DAYS"" in ""/etc/login.defs"" with the following command:



# grep -i pass_max_days /etc/login.defs

PASS_MAX_DAYS     60



If the ""PASS_MAX_DAYS"" parameter value is not 60 or less, or is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to enforce a 60-day maximum password lifetime restriction.



Add the following line in ""/etc/login.defs"" (or modify the line to have the required value):



PASS_MAX_DAYS     60
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000199

The information system enforces maximum password lifetime restrictions.

NIST SP 800-53 :: IA-5 (1) (d)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (d)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
