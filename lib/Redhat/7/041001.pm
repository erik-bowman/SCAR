# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::041001
#
# VULN ID
#   V-72417
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000375-GPOS-00160
#
# RULE ID
#   SV-87041r2_rule
#
# STIG ID
#   RHEL-07-041001
#
# RULE TITLE
#   The operating system must have the required packages for multifactor authentication installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::041001;

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
    $self->{VULN_ID} = 'V-72417';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000375-GPOS-00160';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-87041r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-041001';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must have the required packages for multifactor authentication installed.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.



Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.



A privileged account is defined as an information system account with authorizations of a privileged user.



Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.



This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).



Requires further clarification from NIST.



Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system has the packages required for multifactor authentication installed.



Check for the presence of the packages required to support multifactor authentication with the following commands:



# yum list installed esc

esc-1.1.0-26.el7.noarch.rpm



# yum list installed pam_pkcs11

pam_pkcs11-0.6.2-14.el7.noarch.rpm



# yum list installed authconfig-gtk

authconfig-gtk-6.1.12-19.el7.noarch.rpm



If the ""esc"", ""pam_pkcs11"", and ""authconfig-gtk"" packages are not installed, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to implement multifactor authentication by installing the required packages.



Install the ""esc"", ""pam_pkcs11"", ""authconfig"", and ""authconfig-gtk"" packages on the system with the following command:



# yum install esc pam_pkcs11 authconfig-gtk
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001948

The information system implements multifactor authentication for remote access to privileged accounts such that one of the factors is provided by a device separate from the system gaining access.

NIST SP 800-53 Revision 4 :: IA-2 (11)



CCI-001953

The information system accepts Personal Identity Verification (PIV) credentials.

NIST SP 800-53 Revision 4 :: IA-2 (12)



CCI-001954

The information system electronically verifies Personal Identity Verification (PIV) credentials.

NIST SP 800-53 Revision 4 :: IA-2 (12)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
