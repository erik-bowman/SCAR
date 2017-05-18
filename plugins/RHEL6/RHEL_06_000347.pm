#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000347
#
# VULN ID
#   V-38619
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000073
#
# RULE ID
#   SV-50420r2_rule
#
# STIG ID
#   RHEL-06-000347
#
# RULE TITLE
#   There must be no .netrc files on the system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000347;

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
    $self->{VULN_ID} = 'V-38619';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000073';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50420r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000347';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'There must be no .netrc files on the system.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Unencrypted passwords for remote FTP servers may be stored in "".netrc"" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check the system for the existence of any "".netrc"" files, run the following command:



$ sudo find /root /home -xdev -name .netrc



If any .netrc files exist, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The "".netrc"" files contain logon information used to auto-logon into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any "".netrc"" files should be removed.
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
