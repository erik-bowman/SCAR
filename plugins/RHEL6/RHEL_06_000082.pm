#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000082
#
# VULN ID
#   V-38511
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50312r2_rule
#
# STIG ID
#   RHEL-06-000082
#
# RULE TITLE
#   IP forwarding for IPv4 must not be enabled, unless the system is a router.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000082;

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
    $self->{VULN_ID} = 'V-38511';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50312r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000082';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'IP forwarding for IPv4 must not be enabled, unless the system is a router.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
IP forwarding permits the kernel to forward packets from one network interface to another. The ability to forward packets between two networks is only appropriate for systems acting as routers.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
The status of the ""net.ipv4.ip_forward"" kernel parameter can be queried by running the following command:



$ sysctl net.ipv4.ip_forward



The output of the command should indicate a value of ""0"". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in ""/etc/sysctl.conf"".



$ grep net.ipv4.ip_forward /etc/sysctl.conf



The ability to forward packets is only appropriate for routers. If the correct value is not returned, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To set the runtime status of the ""net.ipv4.ip_forward"" kernel parameter, run the following command:



# sysctl -w net.ipv4.ip_forward=0



If this is not the system's default value, add the following line to ""/etc/sysctl.conf"":



net.ipv4.ip_forward = 0
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
