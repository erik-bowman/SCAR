# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040630
#
# VULN ID
#   V-72287
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86911r1_rule
#
# STIG ID
#   RHEL-07-040630
#
# RULE TITLE
#   The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040630;

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
    return 'V-72287';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86911r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040630';
}

sub get_rule_title {
    return
        'The system must not respond to Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) echoes sent to a broadcast address.';
}

sub get_discussion {
    return <<'DISCUSSION';
Responding to broadcast (ICMP) echoes facilitates network mapping and provides a vector for amplification attacks.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the system does not respond to IPv4 ICMP echoes sent to a broadcast address.



Check the value of the ""icmp_echo_ignore_broadcasts"" variable with the following command:



# /sbin/sysctl -a | grep  net.ipv4.icmp_echo_ignore_broadcasts

net.ipv4.icmp_echo_ignore_broadcasts=1



If the returned line does not have a value of ""1"", a line is not returned, or the retuned line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the system to the required kernel parameter by adding the following line to ""/etc/sysctl.conf"" (or modify the line to have the required value):



net.ipv4.icmp_echo_ignore_broadcasts=1
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
