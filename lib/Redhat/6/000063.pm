# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000063
#
# VULN ID
#   V-38576
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000120
#
# RULE ID
#   SV-50377r1_rule
#
# STIG ID
#   RHEL-06-000063
#
# RULE TITLE
#   The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000063;

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
    return 'V-38576';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000120';
}

sub get_rule_id {
    return 'SV-50377r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000063';
}

sub get_rule_title {
    return
        'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (login.defs).';
}

sub get_discussion {
    return <<'DISCUSSION';
Using a stronger hashing algorithm makes password cracking attacks more difficult.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/login.defs"" and ensure the following line appears:



ENCRYPT_METHOD SHA512





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
In ""/etc/login.defs"", add or correct the following line to ensure the system will use SHA-512 as the hashing algorithm:



ENCRYPT_METHOD SHA512
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
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
