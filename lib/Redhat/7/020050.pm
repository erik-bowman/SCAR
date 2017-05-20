# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020050
#
# VULN ID
#   V-71977
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000366-GPOS-00153
#
# RULE ID
#   SV-86601r1_rule
#
# STIG ID
#   RHEL-07-020050
#
# RULE TITLE
#   The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020050;

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
    return 'V-71977';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000366-GPOS-00153';
}

sub get_rule_id {
    return 'SV-86601r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020050';
}

sub get_rule_title {
    return
        'The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components from a repository without verification they have been digitally signed using a certificate that is issued by a Certificate Authority (CA) that is recognized and approved by the organization.';
}

sub get_discussion {
    return <<'DISCUSSION';
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.



Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.



Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved CA.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components from a repository without verification that they have been digitally signed using a certificate that is recognized and approved by the organization.



Check that yum verifies the signature of packages from a repository prior to install with the following command:



# grep gpgcheck /etc/yum.conf

gpgcheck=1



If ""gpgcheck"" is not set to ""1"", or if options are missing or commented out, ask the System Administrator how the certificates for patches and other operating system components are verified.



If there is no process to validate certificates that is approved by the organization, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to verify the signature of packages from a repository prior to install by setting the following option in the ""/etc/yum.conf"" file:



gpgcheck=1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001749

The information system prevents the installation of organization-defined software components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

NIST SP 800-53 Revision 4 :: CM-5 (3)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__