# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000095
#
# VULN ID
#   V-38539
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000142
#
# RULE ID
#   SV-50340r2_rule
#
# STIG ID
#   RHEL-06-000095
#
# RULE TITLE
#   The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000095;

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
    return 'V-38539';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000142';
}

sub get_rule_id {
    return 'SV-50340r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000095';
}

sub get_rule_title {
    return
        'The system must be configured to use TCP syncookies when experiencing a TCP SYN flood.';
}

sub get_discussion {
    return <<'DISCUSSION';
A TCP SYN flood attack can cause a denial of service by filling a system's TCP connection table with connections in the SYN_RCVD state. Syncookies can be used to track a connection when a subsequent ACK is received, verifying the initiator is attempting a valid connection and is not a flood source. This feature is activated when a flood condition is detected, and enables the system to continue servicing valid connection requests.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The status of the ""net.ipv4.tcp_syncookies"" kernel parameter can be queried by running the following command:



$ sysctl net.ipv4.tcp_syncookies



The output of the command should indicate a value of ""1"". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in ""/etc/sysctl.conf"".



$ grep net.ipv4.tcp_syncookies /etc/sysctl.conf



If the correct value is not returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the runtime status of the ""net.ipv4.tcp_syncookies"" kernel parameter, run the following command:



# sysctl -w net.ipv4.tcp_syncookies=1



If this is not the system's default value, add the following line to ""/etc/sysctl.conf"":



net.ipv4.tcp_syncookies = 1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001095

The information system manages excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial of service attacks.

NIST SP 800-53 :: SC-5 (2)

NIST SP 800-53A :: SC-5 (2).1

NIST SP 800-53 Revision 4 :: SC-5 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
