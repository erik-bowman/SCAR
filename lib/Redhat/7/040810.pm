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

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-72315';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86939r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040810';
}

sub get_rule_title {
    return
        'The system access control program must be configured to grant or deny system access to specific hosts and services.';
}

sub get_discussion {
    return <<'DISCUSSION';
If the systems access control program is not configured with appropriate rules for allowing and denying access to system network resources, services may be accessible to unauthorized hosts.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If ""firewalld"" is installed and active on the system, configure rules for allowing specific services and hosts.



If ""tcpwrappers"" is installed, configure the ""/etc/hosts.allow"" and ""/etc/hosts.deny"" to allow or deny access to specific hosts.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
