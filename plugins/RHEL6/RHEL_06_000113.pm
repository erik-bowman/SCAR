#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000113
#
# VULN ID
#   V-38555
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000152
#
# RULE ID
#   SV-50356r2_rule
#
# STIG ID
#   RHEL-06-000113
#
# RULE TITLE
#   The system must employ a local IPv4 firewall.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000113;

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
    $self->{VULN_ID} = 'V-38555';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000152';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50356r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000113';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The system must employ a local IPv4 firewall.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The ""iptables"" service provides the system's host-based firewalling capability for IPv4 and ICMP.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the system is a cross-domain system, this is not applicable.



Run the following command to determine the current status of the ""iptables"" service:



# service iptables status



If the service is not running, it should return the following:



iptables: Firewall is not running.





If the service is not running, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""iptables"" service can be enabled with the following commands:



# chkconfig iptables on

# service iptables start
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001118

The information system implements host-based boundary protection mechanisms for servers, workstations, and mobile devices.

NIST SP 800-53 :: SC-7 (12)

NIST SP 800-53A :: SC-7 (12).1




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
