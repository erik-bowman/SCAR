#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000234
#
# VULN ID
#   V-38611
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000106
#
# RULE ID
#   SV-50412r1_rule
#
# STIG ID
#   RHEL-06-000234
#
# RULE TITLE
#   The SSH daemon must ignore .rhosts files.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000234;

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
    $self->{VULN_ID} = 'V-38611';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000106';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50412r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000234';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The SSH daemon must ignore .rhosts files.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To determine how the SSH daemon's ""IgnoreRhosts"" option is set, run the following command:



# grep -i IgnoreRhosts /etc/ssh/sshd_config



If no line, a commented line, or a line indicating the value ""yes"" is returned, then the required value is set.

If the required value is not set, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
SSH can emulate the behavior of the obsolete rsh command in allowing users to enable insecure access to their accounts via "".rhosts"" files.



To ensure this behavior is disabled, add or correct the following line in ""/etc/ssh/sshd_config"":



IgnoreRhosts yes
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000766

The information system implements multifactor authentication for network access to non-privileged accounts.

NIST SP 800-53 :: IA-2 (2)

NIST SP 800-53A :: IA-2 (2).1

NIST SP 800-53 Revision 4 :: IA-2 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
