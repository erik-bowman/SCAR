#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000008
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

package RHEL_06_000008;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-38476';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000090';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50276r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000008';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Vendor-provided cryptographic certificates must be installed to verify the integrity of system software.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The Red Hat GPG keys are necessary to cryptographically verify packages are from Red Hat.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure that the GPG keys are installed, run:



$ rpm -q gpg-pubkey



The command should return the strings below:



gpg-pubkey-fd431d51-4ae0493b

gpg-pubkey-2fa658e0-45700c69



If the Red Hat GPG Keys are not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To ensure the system can cryptographically verify base software packages come from Red Hat (and to connect to the Red Hat Network to receive them), the Red Hat GPG keys must be installed properly. To install the Red Hat GPG keys, run:



# rhn_register



If the system is not connected to the Internet or an RHN Satellite, then install the Red Hat GPG keys from trusted media such as the Red Hat installation CD-ROM or DVD. Assuming the disc is mounted in ""/media/cdrom"", use the following command as the root user to import them into the keyring:



# rpm --import /media/cdrom/RPM-GPG-KEY
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000352

The information system prevents the installation of organization defined critical software programs that are not signed with a certificate that is recognized and approved by the organization.

NIST SP 800-53 :: CM-5 (3)

NIST SP 800-53A :: CM-5 (3).1 (ii)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
