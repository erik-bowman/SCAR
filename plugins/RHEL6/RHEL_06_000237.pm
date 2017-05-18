#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000237
#
# VULN ID
#   V-38613
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000109
#
# RULE ID
#   SV-50414r1_rule
#
# STIG ID
#   RHEL-06-000237
#
# RULE TITLE
#   The system must not permit root logins using remote access programs such as ssh.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000237;

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
    $self->{VULN_ID} = 'V-38613';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000109';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50414r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000237';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must not permit root logins using remote access programs such as ssh.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To determine how the SSH daemon's ""PermitRootLogin"" option is set, run the following command:



# grep -i PermitRootLogin /etc/ssh/sshd_config



If a line indicating ""no"" is returned, then the required value is set.

If the required value is not set, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in ""/etc/ssh/sshd_config"":



PermitRootLogin no
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000770

The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.

NIST SP 800-53 :: IA-2 (5) (b)

NIST SP 800-53A :: IA-2 (5).2 (ii)

NIST SP 800-53 Revision 4 :: IA-2 (5)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
