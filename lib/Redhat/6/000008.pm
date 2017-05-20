# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000008
#
# VULN ID
#   V-38476
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000090
#
# RULE ID
#   SV-50276r3_rule
#
# STIG ID
#   RHEL-06-000008
#
# RULE TITLE
#   Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000008;

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
    return 'V-38476';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000090';
}

sub get_rule_id {
    return 'SV-50276r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000008';
}

sub get_rule_title {
    return
        'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.';
}

sub get_discussion {
    return <<'DISCUSSION';
The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure that the GPG keys are installed, run:



$ rpm -q gpg-pubkey



The command should return the strings below:



gpg-pubkey-fd431d51-4ae0493b

gpg-pubkey-2fa658e0-45700c69



If the Red Hat GPG Keys are not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG keys must be installed properly. To install the Red Hat GPG keys, run:



# rhn_register



If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG keys from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in ""/media/cdrom"", use the following command as the root user to import them into the keyring:



# rpm --import /media/cdrom/RPM-GPG-KEY
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000352

The information system prevents the installation of organization defined critical software programs that are not signed with a certificate that is recognized and approved by the organization.

NIST SP 800-53 :: CM-5 (3)

NIST SP 800-53A :: CM-5 (3).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
