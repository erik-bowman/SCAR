#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000214
#
# VULN ID
#   V-38594
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000033
#
# RULE ID
#   SV-50395r2_rule
#
# STIG ID
#   RHEL-06-000214
#
# RULE TITLE
#   The rshd service must not be running.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000214;

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
    $self->{VULN_ID} = 'V-38594';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000033';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50395r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000214';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The rshd service must not be running.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The rsh service uses unencrypted network communications, which means that data from the login session, including passwords and all other information transmitted during the session, can be stolen by eavesdroppers on the network.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check that the ""rsh"" service is disabled in system boot configuration, run the following command:



# chkconfig ""rsh"" --list



Output should indicate the ""rsh"" service has either not been installed, or has been disabled, as shown in the example below:



# chkconfig ""rsh"" --list

rsh off

OR

error reading information on service rsh: No such file or directory





If the service is running, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""rsh"" service, which is available with the ""rsh-server"" package and runs as a service through xinetd, should be disabled. The ""rsh"" service can be disabled with the following command:



# chkconfig rsh off
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000068

The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
