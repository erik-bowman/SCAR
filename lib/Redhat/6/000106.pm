# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000106
#
# VULN ID
#   V-38551
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000145
#
# RULE ID
#   SV-50352r3_rule
#
# STIG ID
#   RHEL-06-000106
#
# RULE TITLE
#   The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000106;

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
    return 'V-38551';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000145';
}

sub get_rule_id {
    return 'SV-50352r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000106';
}

sub get_rule_title {
    return
        'The operating system must connect to external networks or information systems only through managed IPv6 interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""ip6tables"" service provides the system's host-based firewalling capability for IPv6 and ICMPv6.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is a cross-domain system, this is not applicable.



If IPV6 is disabled, this is not applicable.



Run the following command to determine the current status of the ""ip6tables"" service:



# service ip6tables status



If the service is not running, it should return the following:



ip6tables: Firewall is not running.





If the service is not running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""ip6tables"" service can be enabled with the following commands:



# chkconfig ip6tables on

# service ip6tables start
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001098

The information system connects to external networks or information systems only through managed interfaces consisting of boundary protection devices arranged in accordance with an organizational security architecture.

NIST SP 800-53 :: SC-7 b

NIST SP 800-53A :: SC-7.1 (iv)

NIST SP 800-53 Revision 4 :: SC-7 c




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
