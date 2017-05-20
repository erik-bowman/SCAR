# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000293
#
# VULN ID
#   V-72817
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   RHEL-06-000293
#
# RULE ID
#   SV-87461r1_rule
#
# STIG ID
#   RHEL-06-000293
#
# RULE TITLE
#   Wireless network adapters must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000293;

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
    return 'V-72817';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'RHEL-06-000293';
}

sub get_rule_id {
    return 'SV-87461r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000293';
}

sub get_rule_title {
    return 'Wireless network adapters must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
The use of wireless networking can introduce many different attack vectors into the organization’s network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
This is N/A for systems that do not have wireless network adapters.



Verify that there are no wireless interfaces configured on the system:



# ifconfig -a





eth0      Link encap:Ethernet  HWaddr b8:ac:6f:65:31:e5

          inet addr:192.168.2.100  Bcast:192.168.2.255  Mask:255.255.255.0

          inet6 addr: fe80::baac:6fff:fe65:31e5/64 Scope:Link

          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1

          RX packets:2697529 errors:0 dropped:0 overruns:0 frame:0

          TX packets:2630541 errors:0 dropped:0 overruns:0 carrier:0

          collisions:0 txqueuelen:1000

          RX bytes:2159382827 (2.0 GiB)  TX bytes:1389552776 (1.2 GiB)

          Interrupt:17



lo        Link encap:Local Loopback

          inet addr:127.0.0.1  Mask:255.0.0.0

          inet6 addr: ::1/128 Scope:Host

          UP LOOPBACK RUNNING  MTU:16436  Metric:1

          RX packets:2849 errors:0 dropped:0 overruns:0 frame:0

          TX packets:2849 errors:0 dropped:0 overruns:0 carrier:0

          collisions:0 txqueuelen:0

          RX bytes:2778290 (2.6 MiB)  TX bytes:2778290 (2.6 MiB)





If a wireless interface is configured, it must be documented and approved by the local Authorizing Official.



If a wireless interface is configured and has not been documented and approved, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system to disable all wireless network interfaces.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001443

The information system protects wireless access to the system using authentication of users and/or devices.

NIST SP 800-53 :: AC-18 (1)

NIST SP 800-53A :: AC-18 (1).1

NIST SP 800-53 Revision 4 :: AC-18 (1)



CCI-001444

The information system protects wireless access to the system using encryption.

NIST SP 800-53 :: AC-18 (1)

NIST SP 800-53A :: AC-18 (1).1

NIST SP 800-53 Revision 4 :: AC-18 (1)



CCI-002418

The information system protects the confidentiality and/or integrity of transmitted information.

NIST SP 800-53 Revision 4 :: SC-8




CCI
}

# ------------------------------------------------------------------------------

1;

__END__