#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010130
#
# VULN ID
#   V-71905
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000070-GPOS-00038
#
# RULE ID
#   SV-86529r2_rule
#
# STIG ID
#   RHEL-07-010130
#
# RULE TITLE
#   When passwords are changed or new passwords are established, the new password must contain at least one lower-case character.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010130;

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
    $self->{VULN_ID} = 'V-71905';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000070-GPOS-00038';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86529r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010130';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'When passwords are changed or new passwords are established, the new password must contain at least one lower-case character.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.



Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Note: The value to require a number of lower-case characters to be set is expressed as a negative number in ""/etc/security/pwquality.conf"".



Check the value for ""lcredit"" in ""/etc/security/pwquality.conf"" with the following command:



# grep lcredit /etc/security/pwquality.conf

lcredit = -1



If the value of ""lcredit"" is not set to a negative value, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to lock an account for the maximum period when three unsuccessful logon attempts in 15 minutes are made.



Modify the first three lines of the ""auth"" section of the ""/etc/pam.d/system-auth-ac"" and ""/etc/pam.d/password-auth-ac"" files to match the following lines:



Note: RHEL 7.3 and later allows for a value of ""never"" for ""unlock_time"". This is an acceptable value but should be used with caution if availability is a concern.



auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800

auth        sufficient     pam_unix.so try_first_pass

auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800



and run the ""authconfig"" command.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000193

The information system enforces password complexity by the minimum number of lower case characters used.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
