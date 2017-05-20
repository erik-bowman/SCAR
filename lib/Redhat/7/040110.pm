# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040110
#
# VULN ID
#   V-72221
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000033-GPOS-00014
#
# RULE ID
#   SV-86845r2_rule
#
# STIG ID
#   RHEL-07-040110
#
# RULE TITLE
#   A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040110;

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
    return 'V-72221';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000033-GPOS-00014';
}

sub get_rule_id {
    return 'SV-86845r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040110';
}

sub get_rule_title {
    return
        'A FIPS 140-2 approved cryptographic algorithm must be used for SSH communications.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.



Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.



FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.



Satisfies: SRG-OS-000033-GPOS-00014, SRG-OS-000120-GPOS-00061, SRG-OS-000125-GPOS-00065, SRG-OS-000250-GPOS-00093, SRG-OS-000393-GPOS-00173
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.



Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.



The location of the ""sshd_config"" file may vary if a different daemon is in use.



Inspect the ""Ciphers"" configuration with the following command:



# grep -i ciphers /etc/ssh/sshd_config

Ciphers aes128-ctr,aes192-ctr,aes256-ctr



If any ciphers other than ""aes128-ctr"", ""aes192-ctr"", or ""aes256-ctr"" are listed, the ""Ciphers"" keyword is missing, or the retuned line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure SSH to use FIPS 140-2 approved cryptographic algorithms.



Add the following line (or modify the line to have the required value) to the ""/etc/ssh/sshd_config"" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).



Ciphers aes128-ctr,aes192-ctr,aes256-ctr



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000068

The information system implements cryptographic mechanisms to protect the confidentiality of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)



CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b



CCI-000803

The information system implements mechanisms for authentication to a cryptographic module that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for such authentication.

NIST SP 800-53 :: IA-7

NIST SP 800-53A :: IA-7.1

NIST SP 800-53 Revision 4 :: IA-7




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
