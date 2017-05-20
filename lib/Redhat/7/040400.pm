# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040400
#
# VULN ID
#   V-72253
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000250-GPOS-00093
#
# RULE ID
#   SV-86877r2_rule
#
# STIG ID
#   RHEL-07-040400
#
# RULE TITLE
#   The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040400;

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
    return 'V-72253';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000250-GPOS-00093';
}

sub get_rule_id {
    return 'SV-86877r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040400';
}

sub get_rule_title {
    return
        'The SSH daemon must be configured to only use Message Authentication Codes (MACs) employing FIPS 140-2 approved cryptographic hash algorithms.';
}

sub get_discussion {
    return <<'DISCUSSION';
DoD information systems are required to use FIPS 140-2 approved cryptographic hash functions. The only SSHv2 hash algorithm meeting this requirement is SHA.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers.



Note: If RHEL-07-021350 is a finding, this is automatically a finding as the system cannot implement FIPS 140-2-approved cryptographic algorithms and hashes.



Check that the SSH daemon is configured to only use MACs employing FIPS 140-2-approved ciphers with the following command:



# grep -i macs /etc/ssh/sshd_config

MACs hmac-sha2-256,hmac-sha2-512



If any ciphers other than ""hmac-sha2-256"" or ""hmac-sha2-512"" are listed or the retuned line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit the ""/etc/ssh/sshd_config"" file to uncomment or add the line for the ""MACs"" keyword and set its value to ""hmac-sha2-256"" and/or ""hmac-sha2-512"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):



MACs hmac-sha2-256,hmac-sha2-512



The SSH service must be restarted for changes to take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001453

The information system implements cryptographic mechanisms to protect the integrity of remote access sessions.

NIST SP 800-53 :: AC-17 (2)

NIST SP 800-53A :: AC-17 (2).1

NIST SP 800-53 Revision 4 :: AC-17 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
