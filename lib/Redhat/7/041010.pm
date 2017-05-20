# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::Redhat::7::041010
#
# VULN ID
#   V-73177
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000424-GPOS-00188
#
# RULE ID
#   SV-87829r1_rule
#
# STIG ID
#   RHEL-07-041010
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

package Redhat::7::Redhat::7::041010;

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
    return 'V-73177';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000424-GPOS-00188';
}

sub get_rule_id {
    return 'SV-87829r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-041010';
}

sub get_rule_title {
    return 'Wireless network adapters must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
The use of wireless networking can introduce many different attack vectors into the organization's network. Common attack vectors such as malicious association and ad hoc networks will allow an attacker to spoof a wireless access point (AP), allowing validated systems to connect to the malicious AP and enabling the attacker to monitor and record network traffic. These malicious APs can also serve to create a man-in-the-middle attack or be used to create a denial of service to valid network resources.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that there are no wireless interfaces configured on the system.



This is N/A for systems that do not have wireless network adapters.



Check for the presence of active wireless interfaces with the following command:



# nmcli device

DEVICE TYPE STATE

eth0 ethernet connected

wlp3s0 wifi disconnected

lo loopback unmanaged



If a wireless interface is configured and its use on the system is not documented with the Information System Security Officer (ISSO), this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system to disable all wireless network interfaces with the following command:



#nmcli radio wifi off
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
