#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000071
#
# VULN ID
#   V-38590
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000030
#
# RULE ID
#   SV-50391r1_rule
#
# STIG ID
#   RHEL-06-000071
#
# RULE TITLE
#   The system must allow locking of the console screen in text mode.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000071;

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
    $self->{VULN_ID} = 'V-38590';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000030';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50391r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000071';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must allow locking of the console screen in text mode.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Installing ""screen"" ensures a console locking capability is available for users who may need to suspend console logins.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to determine if the ""screen"" package is installed:



# rpm -q screen





If the package is not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To enable console screen locking when in text mode, install the ""screen"" package:



# yum install screen



Instruct users to begin new terminal sessions with the following command:



$ screen



The console can now be locked with the following key combination:



ctrl+a x
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000058

The information system provides the capability for users to directly initiate session lock mechanisms.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
