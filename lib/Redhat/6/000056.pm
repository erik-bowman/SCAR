# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000056
#
# VULN ID
#   V-38482
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000071
#
# RULE ID
#   SV-50282r1_rule
#
# STIG ID
#   RHEL-06-000056
#
# RULE TITLE
#   The system must require passwords to contain at least one numeric character.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000056;

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
    return 'V-38482';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000071';
}

sub get_rule_id {
    return 'SV-50282r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000056';
}

sub get_rule_title {
    return
        'The system must require passwords to contain at least one numeric character.';
}

sub get_discussion {
    return <<'DISCUSSION';
Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check how many digits are required in a password, run the following command:



$ grep pam_cracklib /etc/pam.d/system-auth



The ""dcredit"" parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as ""dcredit=-1"".

If dcredit is not found or not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The pam_cracklib module's ""dcredit"" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit. Add ""dcredit=-1"" after pam_cracklib.so to require use of a digit in passwords.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000194

The information system enforces password complexity by the minimum number of numeric characters used.

NIST SP 800-53 :: IA-5 (1) (a)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (a)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
