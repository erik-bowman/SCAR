#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000290
#
# VULN ID
#   V-38674
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50475r1_rule
#
# STIG ID
#   RHEL-06-000290
#
# RULE TITLE
#   X Windows must not be enabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000290;

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
    $self->{VULN_ID} = 'V-38674';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000248';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50475r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000290';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'X Windows must not be enabled unless required.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Unnecessary services should be disabled to decrease the attack surface of the system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To verify the default runlevel is 3, run the following command:



# grep initdefault /etc/inittab



The output should show the following:



id:3:initdefault:





If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Setting the system's runlevel to 3 will prevent automatic startup of the X server. To do so, ensure the following line in ""/etc/inittab"" features a ""3"" as shown:



id:3:initdefault:
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
