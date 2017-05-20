# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040641
#
# VULN ID
#   V-73175
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-87827r2_rule
#
# STIG ID
#   RHEL-07-040641
#
# RULE TITLE
#   The system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040641;

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
    return 'V-73175';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-87827r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040641';
}

sub get_rule_title {
    return
        'The system must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.';
}

sub get_discussion {
    return <<'DISCUSSION';
ICMP redirect messages are used by routers to inform hosts that a more direct route exists for a particular destination. These messages modify the host's route table and are unauthenticated. An illicit ICMP redirect message could result in a man-in-the-middle attack.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the system ignores IPv4 ICMP redirect messages.



Check the value of the ""accept_redirects"" variables with the following command:



# /sbin/sysctl -a | grep  'net.ipv4.conf.all.accept_redirects'



net.ipv4.conf.all.accept_redirects=0



If both of the returned lines do not have a value of ""0"", or a line is not returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the system to ignore IPv4 ICMP redirect messages by adding the following line to ""/etc/sysctl.conf"" (or modify the line to have the required value):



net.ipv4.conf.all.accept_redirects = 0
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
