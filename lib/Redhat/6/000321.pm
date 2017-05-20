# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000321
#
# VULN ID
#   V-38687
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000160
#
# RULE ID
#   SV-50488r3_rule
#
# STIG ID
#   RHEL-06-000321
#
# RULE TITLE
#   The system must provide VPN connectivity for communications over untrusted networks.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000321;

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
    return 'V-38687';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000160';
}

sub get_rule_id {
    return 'SV-50488r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000321';
}

sub get_rule_title {
    return
        'The system must provide VPN connectivity for communications over untrusted networks.';
}

sub get_discussion {
    return <<'DISCUSSION';
Providing the ability for remote users or systems to initiate a secure VPN connection protects information when it is transmitted over a wide area network.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system does not communicate over untrusted networks, this is not applicable.



Run the following command to determine if the ""libreswan"" package is installed:



# rpm -q libreswan



If the package is not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""libreswan"" package provides an implementation of IPsec and IKE, which permits the creation of secure tunnels over untrusted networks. The ""libreswan"" package can be installed with the following command:



# yum install libreswan


FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001130

The information system protects the confidentiality of transmitted information.

NIST SP 800-53 :: SC-9

NIST SP 800-53A :: SC-9.1




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
