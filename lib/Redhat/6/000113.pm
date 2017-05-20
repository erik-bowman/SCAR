# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000113
#
# VULN ID
#   V-38555
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000152
#
# RULE ID
#   SV-50356r2_rule
#
# STIG ID
#   RHEL-06-000113
#
# RULE TITLE
#   The system must employ a local IPv4 firewall.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000113;

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
    return 'V-38555';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000152';
}

sub get_rule_id {
    return 'SV-50356r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000113';
}

sub get_rule_title {
    return 'The system must employ a local IPv4 firewall.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""iptables"" service provides the system's host-based firewalling capability for IPv4 and ICMP.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is a cross-domain system, this is not applicable.



Run the following command to determine the current status of the ""iptables"" service:



# service iptables status



If the service is not running, it should return the following:



iptables: Firewall is not running.





If the service is not running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""iptables"" service can be enabled with the following commands:



# chkconfig iptables on

# service iptables start
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001118

The information system implements host-based boundary protection mechanisms for servers, workstations, and mobile devices.

NIST SP 800-53 :: SC-7 (12)

NIST SP 800-53A :: SC-7 (12).1




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
