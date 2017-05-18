#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000321
#
# VULN ID
#   V-38687
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000160
#
# RULE ID
#   SV-50488r3_rule
#
# STIG ID
#   RHEL-06-000321
#
# RULE TITLE
#   The system must provide VPN connectivity for communications over untrusted networks.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000321;

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
    $self->{VULN_ID} = 'V-38687';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000160';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50488r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000321';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must provide VPN connectivity for communications over untrusted networks.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the system does not communicate over untrusted networks, this is not applicable.



Run the following command to determine if the ""libreswan"" package is installed:



# rpm -q libreswan



If the package is not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""libreswan"" package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The ""libreswan"" package can be installed with the following command:



# yum install libreswan


FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001130

The information system protects the confidentiality of transmitted information.

NIST SP 800-53 :: SC-9

NIST SP 800-53A :: SC-9.1




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
