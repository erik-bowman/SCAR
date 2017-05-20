# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000091
#
# VULN ID
#   V-38533
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50334r3_rule
#
# STIG ID
#   RHEL-06-000091
#
# RULE TITLE
#   The system must ignore ICMPv4 redirect messages by default.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000091;

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
    return 'V-38533';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50334r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000091';
}

sub get_rule_title {
    return 'The system must ignore ICMPv4 redirect messages by default.';
}

sub get_discussion {
    return <<'DISCUSSION';
This feature of the IPv4 protocol has few legitimate uses. It should be disabled unless it is absolutely required.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The status of the ""net.ipv4.conf.default.accept_redirects"" kernel parameter can be queried by running the following command:



$ sysctl net.ipv4.conf.default.accept_redirects



The output of the command should indicate a value of ""0"". If this value is not the default value, investigate how it could have been adjusted at runtime, and verify it is not set improperly in ""/etc/sysctl.conf"".



$ grep net.ipv4.conf.default.accept_redirects /etc/sysctl.conf



If the correct value is not returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the runtime status of the ""net.ipv4.conf.default.accept_redirects"" kernel parameter, run the following command:



# sysctl -w net.ipv4.conf.default.accept_redirects=0



If this is not the system's default value, add the following line to ""/etc/sysctl.conf"":



net.ipv4.conf.default.accept_redirects = 0
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
