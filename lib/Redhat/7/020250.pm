# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020250
#
# VULN ID
#   V-71997
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86621r2_rule
#
# STIG ID
#   RHEL-07-020250
#
# RULE TITLE
#   The operating system must be a vendor supported release.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020250;

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
    return 'V-71997';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86621r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020250';
}

sub get_rule_title {
    return 'The operating system must be a vendor supported release.';
}

sub get_discussion {
    return <<'DISCUSSION';
An operating system release is considered ""supported"" if the vendor continues to provide security patches for the product. With an unsupported release, it will not be possible to resolve security issues discovered in the system software.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the version of the operating system is vendor supported.



Check the version of the operating system with the following command:



# cat /etc/redhat-release



Red Hat Enterprise Linux Server release 7.2 (Maipo)



Current End of Life for RHEL 7.2 is Q4 2020.



Current End of Life for RHEL 7.3 is 30 June 2024.



If the release is not supported by the vendor, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Upgrade to a supported version of the operating system.
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
