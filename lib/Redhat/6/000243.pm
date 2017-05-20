# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000243
#
# VULN ID
#   V-38617
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000169
#
# RULE ID
#   SV-50418r1_rule
#
# STIG ID
#   RHEL-06-000243
#
# RULE TITLE
#   The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000243;

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
    return 'V-38617';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000169';
}

sub get_rule_id {
    return 'SV-50418r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000243';
}

sub get_rule_title {
    return
        'The SSH daemon must be configured to use only FIPS 140-2 approved ciphers.';
}

sub get_discussion {
    return <<'DISCUSSION';
Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command:



# grep Ciphers /etc/ssh/sshd_config



The output should contain only those ciphers which are FIPS-approved, namely, the AES and 3DES ciphers.

If that is not the case, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Limit the ciphers to those algorithms which are FIPS-approved. Counter (CTR) mode is also preferred over cipher-block chaining (CBC) mode. The following line in ""/etc/ssh/sshd_config"" demonstrates use of FIPS-approved ciphers:



Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc



The man page ""sshd_config(5)"" contains a list of supported ciphers.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001144

The information system implements required cryptographic protections using cryptographic modules that comply with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NIST SP 800-53 :: SC-13

NIST SP 800-53A :: SC-13.1




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
