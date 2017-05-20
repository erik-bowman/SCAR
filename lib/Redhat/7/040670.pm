# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040670
#
# VULN ID
#   V-72295
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86919r1_rule
#
# STIG ID
#   RHEL-07-040670
#
# RULE TITLE
#   Network interfaces must not be in promiscuous mode.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040670;

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
    return 'V-72295';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86919r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040670';
}

sub get_rule_title {
    return 'Network interfaces must not be in promiscuous mode.';
}

sub get_discussion {
    return <<'DISCUSSION';
Network interfaces in promiscuous mode allow for the capture of all network traffic visible to the system. If unauthorized individuals can access these applications, it may allow then to collect information such as logon IDs, passwords, and key exchanges between systems.



If the system is being used to perform a network troubleshooting function, the use of these tools must be documented with the Information System Security Officer (ISSO) and restricted to only authorized personnel.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify network interfaces are not in promiscuous mode unless approved by the ISSO and documented.



Check for the status with the following command:



# ip link | grep -i promisc



If network interfaces are found on the system in promiscuous mode and their use has not been approved by the ISSO and documented, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure network interfaces to turn off promiscuous mode unless approved by the ISSO and documented.



Set the promiscuous mode of an interface to off with the following command:



#ip link set dev <devicename> multicast off promisc off
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
