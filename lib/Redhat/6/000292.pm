# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000292
#
# VULN ID
#   V-38679
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50480r2_rule
#
# STIG ID
#   RHEL-06-000292
#
# RULE TITLE
#   The DHCP client must be disabled if not needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000292;

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
    return 'V-38679';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50480r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000292';
}

sub get_rule_title {
    return 'The DHCP client must be disabled if not needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
DHCP relies on trusting the local network. If the local network is not trusted, then it should not be used. However, the automatic configuration provided by DHCP is commonly used and the alternative, manual configuration, presents an unacceptable burden in many circumstances.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that DHCP is not being used, examine the following file for each interface.



# /etc/sysconfig/network-scripts/ifcfg-[IFACE]



If there is any network interface without a associated ""ifcfg"" file, this is a finding.



Look for the following:



BOOTPROTO=none



Also verify the following, substituting the appropriate values based on your site's addressing scheme:



NETMASK=[local LAN netmask]

IPADDR=[assigned IP address]

GATEWAY=[local LAN default gateway]





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
For each interface [IFACE] on the system (e.g. eth0), edit ""/etc/sysconfig/network-scripts/ifcfg-[IFACE]"" and make the following changes.



Correct the BOOTPROTO line to read:



BOOTPROTO=none





Add or correct the following lines, substituting the appropriate values based on your site's addressing scheme:



NETMASK=[local LAN netmask]

IPADDR=[assigned IP address]

GATEWAY=[local LAN default gateway]
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
