#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000357
#
# VULN ID
#   V-38501
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000249
#
# RULE ID
#   SV-50302r4_rule
#
# STIG ID
#   RHEL-06-000357
#
# RULE TITLE
#   The system must disable accounts after excessive login failures within a 15-minute interval.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000357;

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
    $self->{VULN_ID} = 'V-38501';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000249';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50302r4_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000357';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must disable accounts after excessive login failures within a 15-minute interval.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Locking out user accounts after a number of incorrect attempts within a specific period of time prevents direct password guessing attacks.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure the failed password attempt policy is configured correctly, run the following command:



$ grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth



For each file, the output should show ""fail_interval=<interval-in-seconds>"" where ""interval-in-seconds"" is 900 (15 minutes) or greater. If the ""fail_interval"" parameter is not set, the default setting of 900 seconds is acceptable. If that is not the case, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Utilizing ""pam_faillock.so"", the ""fail_interval"" directive configures the system to lock out accounts after a number of incorrect logon attempts. Modify the content of both ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" as follows:



Add the following line immediately before the ""pam_unix.so"" statement in the ""AUTH"" section:



auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately after the ""pam_unix.so"" statement in the ""AUTH"" section:



auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately before the ""pam_unix.so"" statement in the ""ACCOUNT"" section:



account required pam_faillock.so



Note that any updates made to ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" may be overwritten by the ""authconfig"" program.  The ""authconfig"" program should not be used.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001452

The information system enforces the organization defined time period during which the limit of consecutive invalid access attempts by a user is counted.

NIST SP 800-53 :: AC-7 a

NIST SP 800-53A :: AC-7.1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
