# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000059
#
# VULN ID
#   V-38571
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000070
#
# RULE ID
#   SV-50372r2_rule
#
# STIG ID
#   RHEL-06-000059
#
# RULE TITLE
#   The system must require passwords to contain at least one lower-case alphabetic character.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000059;

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
    return 'V-38571';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000070';
}

sub get_rule_id {
    return 'SV-50372r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000059';
}

sub get_rule_title {
    return
        'The system must require passwords to contain at least one lower-case alphabetic character.';
}

sub get_discussion {
    return <<'DISCUSSION';
Requiring a minimum number of lower-case characters makes password guessing attacks more difficult by ensuring a larger search space.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check how many lower-case characters are required in a password, run the following command:



$ grep pam_cracklib /etc/pam.d/system-auth



The ""lcredit"" parameter (as a negative number) will indicate how many lower-case characters are required. The DoD requires at least one lower-case character in a password. This would appear as ""lcredit=-1"".



If lcredit is not found or not set to the required value, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The pam_cracklib module's ""lcredit="" parameter controls requirements for usage of lower-case letters in a password. When set to a negative number, any password will be required to contain that many lower-case characters. Add ""lcredit=-1"" after pam_cracklib.so to require use of a lower-case character in passwords.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000193

The information system enforces password complexity by the minimum number of lower case characters used.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
