# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000064
#
# VULN ID
#   V-38577
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000120
#
# RULE ID
#   SV-50378r1_rule
#
# STIG ID
#   RHEL-06-000064
#
# RULE TITLE
#   The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000064;

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
    return 'V-38577';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000120';
}

sub get_rule_id {
    return 'SV-50378r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000064';
}

sub get_rule_title {
    return
        'The system must use a FIPS 140-2 approved cryptographic hashing algorithm for generating account password hashes (libuser.conf).';
}

sub get_discussion {
    return <<'DISCUSSION';
Using a stronger hashing algorithm makes password cracking attacks more difficult.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/libuser.conf"" and ensure the following line appears in the ""[default]"" section:



crypt_style = sha512





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
In ""/etc/libuser.conf"", add or correct the following line in its ""[defaults]"" section to ensure the system will use the SHA-512 algorithm for password hashing:



crypt_style = sha512
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
