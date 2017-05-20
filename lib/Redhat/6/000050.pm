# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000050
#
# VULN ID
#   V-38475
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000078
#
# RULE ID
#   SV-50275r3_rule
#
# STIG ID
#   RHEL-06-000050
#
# RULE TITLE
#   The system must require passwords to contain a minimum of 15 characters.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000050;

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
    return 'V-38475';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000078';
}

sub get_rule_id {
    return 'SV-50275r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000050';
}

sub get_rule_title {
    return
        'The system must require passwords to contain a minimum of 15 characters.';
}

sub get_discussion {
    return <<'DISCUSSION';
Requiring a minimum password length makes password cracking attacks more difficult by ensuring a larger search space. However, any security benefit from an onerous requirement must be carefully weighed against usability problems, support costs, or counterproductive behavior that may result.



While it does not negate the password length requirement, it is preferable to migrate from a password-based authentication scheme to a stronger one based on PKI (public key infrastructure).
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the minimum password length, run the command:



$ grep PASS_MIN_LEN /etc/login.defs



The DoD requirement is ""15"".



If it is not set to the required value, this is a finding.



$ grep -E ‘pam_cracklib.so.*minlen’ /etc/pam.d/*



If no results are returned, this is not a finding.



If any results are returned and are not set to ""15"" or greater, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify password length requirements for new accounts, edit the file ""/etc/login.defs"" and add or correct the following lines:



PASS_MIN_LEN 15



The DoD requirement is ""15"". If a program consults ""/etc/login.defs"" and also another PAM module (such as ""pam_cracklib"") during a password change operation, then the most restrictive must be satisfied.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000205

The information system enforces minimum password length.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (i)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
