#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000241
#
# VULN ID
#   V-38616
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000242
#
# RULE ID
#   SV-50417r1_rule
#
# STIG ID
#   RHEL-06-000241
#
# RULE TITLE
#   The SSH daemon must not permit user environment settings.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000241;

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
    $self->{VULN_ID} = 'V-38616';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000242';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50417r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000241';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The SSH daemon must not permit user environment settings.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
SSH environment options potentially allow users to bypass access restriction in some configurations.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure users are not able to present environment daemons, run the following command:



# grep PermitUserEnvironment /etc/ssh/sshd_config



If properly configured, output should be:



PermitUserEnvironment no





If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in ""/etc/ssh/sshd_config"":



PermitUserEnvironment no
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001414

The information system enforces approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

NIST SP 800-53 :: AC-4

NIST SP 800-53A :: AC-4.1 (iii)

NIST SP 800-53 Revision 4 :: AC-4




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
