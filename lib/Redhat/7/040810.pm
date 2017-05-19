# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040810
#
# VULN ID
#   V-72315
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86939r1_rule
#
# STIG ID
#   RHEL-07-040810
#
# RULE TITLE
#   The system access control program must be configured to grant or deny system access to specific hosts and services.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040810;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

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
    $self->{VULN_ID} = 'V-72315';
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
    $self->{RULE_ID} = 'SV-86939r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040810';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system access control program must be configured to grant or deny system access to specific hosts and services.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the ""firewalld"" package is not installed, ask the System Administrator (SA) if another firewall application (such as iptables) is installed. If an application firewall is not installed, this is a finding.



Verify the system's access control program is configured to grant or deny system access to specific hosts.



Check to see if ""firewalld"" is active with the following command:



# systemctl status firewalld

firewalld.service - firewalld - dynamic firewall daemon

   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)

   Active: active (running) since Sun 2014-04-20 14:06:46 BST; 30s ago



If ""firewalld"" is active, check to see if it is configured to grant or deny access to specific hosts or services with the following commands:



# firewall-cmd --get-default-zone

public



# firewall-cmd --list-all --zone=public

public (default, active)

  interfaces: eth0

  sources:

  services: mdns ssh

  ports:

  masquerade: no

  forward-ports:

  icmp-blocks:

  rich rules:

 rule family=""ipv4"" source address=""92.188.21.1/24"" accept

 rule family=""ipv4"" source address=""211.17.142.46/32"" accept



If ""firewalld"" is not active, determine whether ""tcpwrappers"" is being used by checking whether the ""hosts.allow"" and ""hosts.deny"" files are empty with the following commands:



# ls -al /etc/hosts.allow

rw-r----- 1 root root 9 Aug  2 23:13 /etc/hosts.allow



# ls -al /etc/hosts.deny

-rw-r----- 1 root root  9 Apr  9  2007 /etc/hosts.deny



If ""firewalld"" and ""tcpwrappers"" are not installed, configured, and active, ask the SA if another access control program (such as iptables) is installed and active. Ask the SA to show that the running configuration grants or denies access to specific hosts or services.



If ""firewalld"" is active and is not configured to grant access to specific hosts and ""tcpwrappers"" is not configured to grant or deny access to specific hosts, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
If ""firewalld"" is installed and active on the system, configure rules for allowing specific services and hosts.



If ""tcpwrappers"" is installed, configure the ""/etc/hosts.allow"" and ""/etc/hosts.deny"" to allow or deny access to specific hosts.
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
