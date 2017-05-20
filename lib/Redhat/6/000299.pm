# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000299
#
# VULN ID
#   V-38693
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50494r2_rule
#
# STIG ID
#   RHEL-06-000299
#
# RULE TITLE
#   The system must require passwords to contain no more than three consecutive repeating characters.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000299;

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
    return 'V-38693';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50494r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000299';
}

sub get_rule_title {
    return
        'The system must require passwords to contain no more than three consecutive repeating characters.';
}

sub get_discussion {
    return <<'DISCUSSION';
Passwords with excessive repeating characters may be more vulnerable to password-guessing attacks.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the maximum value for consecutive repeating characters, run the following command:



$ grep pam_cracklib /etc/pam.d/system-auth



Look for the value of the ""maxrepeat"" parameter. The DoD requirement is 3.

If maxrepeat is not found or not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The pam_cracklib module's ""maxrepeat"" parameter controls requirements for consecutive repeating characters. When set to a positive number, it will reject passwords which contain more than that number of consecutive characters. Add ""maxrepeat=3"" after pam_cracklib.so to prevent a run of (3 + 1) or more identical characters.



password required pam_cracklib.so maxrepeat=3
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
