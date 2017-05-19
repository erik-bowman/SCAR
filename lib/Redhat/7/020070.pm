# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020070
#
# VULN ID
#   V-71981
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000366-GPOS-00153
#
# RULE ID
#   SV-86605r1_rule
#
# STIG ID
#   RHEL-07-020070
#
# RULE TITLE
#   The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020070;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-71981';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000366-GPOS-00153';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86605r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020070';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must prevent the installation of software, patches, service packs, device drivers, or operating system components of packages without verification of the repository metadata.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.



Accordingly, patches, service packs, device drivers, or operating system components must be signed with a certificate recognized and approved by the organization.



Verifying the authenticity of the software prior to installation validates the integrity of the patch or upgrade received from a vendor. This ensures the software has not been tampered with and that it has been provided by a trusted vendor. Self-signed certificates are disallowed by this requirement. The operating system should not have to verify the software again. This requirement does not mandate DoD certificates for this purpose; however, the certificate used to verify the software must be from an approved Certificate Authority.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system prevents the installation of patches, service packs, device drivers, or operating system components of local packages without verification of the repository metadata.



Check that yum verifies the package metadata prior to install with the following command:



# grep repo_gpgcheck /etc/yum.conf

repo_gpgcheck=1



If ""repo_gpgcheck"" is not set to ""1"", or if options are missing or commented out, ask the System Administrator how the metadata of local packages and other operating system components are verified.



If there is no process to validate the metadata of packages that is approved by the organization, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to verify the repository metadata by setting the following options in the ""/etc/yum.conf"" file:



repo_gpgcheck=1
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001749

The information system prevents the installation of organization-defined software components without verification the software component has been digitally signed using a certificate that is recognized and approved by the organization.

NIST SP 800-53 Revision 4 :: CM-5 (3)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
