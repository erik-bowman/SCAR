#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_040520
#
# VULN ID
#   V-72273
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86897r1_rule
#
# STIG ID
#   RHEL-07-040520
#
# RULE TITLE
#   The operating system must enable an application firewall, if available.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_040520;

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
    $self->{VULN_ID} = 'V-72273';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86897r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040520';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must enable an application firewall, if available.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.



Satisfies: SRG-OS-000480-GPOS-00227, SRG-OS-000480-GPOS-00231, SRG-OS-000480-GPOS-00232
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system enabled an application firewall.



Check to see if ""firewalld"" is installed with the following command:



# yum list installed firewalld

firewalld-0.3.9-11.el7.noarch.rpm



If the ""firewalld"" package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed.



If an application firewall is not installed, this is a finding.



Check to see if the firewall is loaded and active with the following command:



# systemctl status firewalld

firewalld.service - firewalld - dynamic firewall daemon



   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)

   Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago



If ""firewalld"" does not show a status of ""loaded"" and ""active"", this is a finding.



Check the state of the firewall:



# firewall-cmd --state

running



If ""firewalld"" does not show a state of ""running"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Ensure the operating system's application firewall is enabled.



Install the ""firewalld"" package, if it is not on the system, with the following command:



# yum install firewalld



Start the firewall via ""systemctl"" with the following command:



# systemctl start firewalld
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
