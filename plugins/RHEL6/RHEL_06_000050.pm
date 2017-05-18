#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000050
#
# VULN ID
#   V-38475
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000078
#
# RULE ID
#   SV-50275r3_rule
#
# STIG ID
#   RHEL-06-000050
#
# RULE TITLE
#   The system must require passwords to contain a minimum of 15 characters.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000050;

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
    $self->{VULN_ID} = 'V-38475';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000078';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50275r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000050';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must require passwords to contain a minimum of 15 characters.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.



While it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check the minimum password length, run the command:



$ grep PASS_MIN_LEN /etc/login.defs



The DoD requirement is ""15"".



If it is not set to the required value, this is a finding.



$ grep -E ‘pam_cracklib.so.*minlen’ /etc/pam.d/*



If no results are returned, this is not a finding.



If any results are returned and are not set to ""15"" or greater, this is a finding.


CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To specify password length requirements for new accounts, edit the file ""/etc/login.defs"" and add or correct the following lines:



PASS_MIN_LEN 15



The DoD requirement is ""15"". If a program consults ""/etc/login.defs"" and also another PAM module (such as ""pam_cracklib"") during a password change operation, then the most restrictive must be satisfied.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000205

The information system enforces minimum password length.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (i)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
