#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010200
#
# VULN ID
#   V-71919
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000073-GPOS-00041
#
# RULE ID
#   SV-86543r1_rule
#
# STIG ID
#   RHEL-07-010200
#
# RULE TITLE
#   The PAM system service must be configured to store only encrypted representations of passwords.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010200;

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
    $self->{VULN_ID} = 'V-71919';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000073-GPOS-00041';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86543r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010200';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The PAM system service must be configured to store only encrypted representations of passwords.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised. Passwords encrypted with a weak algorithm are no more protected than if they are kept in plain text.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the PAM system service is configured to store only encrypted representations of passwords. The strength of encryption that must be used to hash passwords for all accounts is SHA512.



Check that the system is configured to create SHA512 hashed passwords with the following command:



# grep password /etc/pam.d/system-auth-ac

password sufficient pam_unix.so sha512



If the ""/etc/pam.d/system-auth-ac"" configuration files allow for password hashes other than SHA512 to be used, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to store only SHA512 encrypted representations of passwords.



Add the following line in ""/etc/pam.d/system-auth-ac"":



password sufficient pam_unix.so sha512



and run the ""authconfig"" command.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000196

The information system, for password-based authentication, stores only encrypted representations of passwords.

NIST SP 800-53 :: IA-5 (1) (c)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (c)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
