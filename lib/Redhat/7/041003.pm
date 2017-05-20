# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::041003
#
# VULN ID
#   V-72433
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000375-GPOS-00160
#
# RULE ID
#   SV-87057r2_rule
#
# STIG ID
#   RHEL-07-041003
#
# RULE TITLE
#   The operating system must implement certificate status checking for PKI authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::041003;

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
    return 'V-72433';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000375-GPOS-00160';
}

sub get_rule_id {
    return 'SV-87057r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-041003';
}

sub get_rule_title {
    return
        'The operating system must implement certificate status checking for PKI authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
Using an authentication device, such as a CAC or token that is separate from the information system, ensures that even if the information system is compromised, that compromise will not affect credentials stored on the authentication device.



Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.



A privileged account is defined as an information system account with authorizations of a privileged user.



Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.



This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (management).



Requires further clarification from NIST.



Satisfies: SRG-OS-000375-GPOS-00160, SRG-OS-000375-GPOS-00161, SRG-OS-000375-GPOS-00162
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system implements certificate status checking for PKI authentication.



Check to see if Online Certificate Status Protocol (OCSP) is enabled on the system with the following command:



# grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf



cert_policy =ca, ocsp_on, signature;

cert_policy =ca, ocsp_on, signature;

cert_policy =ca, ocsp_on, signature;



There should be at least three lines returned. All lines must match the example output; specifically that ""oscp_on"" must be included in the ""cert_policy"" line.



If ""oscp_on"" is present in all ""cert_policy"" lines, this is not a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to do certificate status checking for PKI authentication.



Modify all of the ""cert_policy"" lines in ""/etc/pam_pkcs11/pam_pkcs11.conf"" to include ""ocsp_on"".
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
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
}

# ------------------------------------------------------------------------------

1;

__END__
