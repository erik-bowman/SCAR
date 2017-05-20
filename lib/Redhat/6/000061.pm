# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000061
#
# VULN ID
#   V-38573
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000021
#
# RULE ID
#   SV-50374r4_rule
#
# STIG ID
#   RHEL-06-000061
#
# RULE TITLE
#   The system must disable accounts after three consecutive unsuccessful logon attempts.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000061;

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
    return 'V-38573';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000021';
}

sub get_rule_id {
    return 'SV-50374r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000061';
}

sub get_rule_title {
    return
        'The system must disable accounts after three consecutive unsuccessful logon attempts.';
}

sub get_discussion {
    return <<'DISCUSSION';
Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure the failed password attempt policy is configured correctly, run the following command:



# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth



The output should show ""deny=3"" for both files.

If that is not the case, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To configure the system to lock out accounts after a number of incorrect logon attempts using ""pam_faillock.so"", modify the content of both ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" as follows:



Add the following line immediately before the ""pam_unix.so"" statement in the ""AUTH"" section:



auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately after the ""pam_unix.so"" statement in the ""AUTH"" section:



auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately before the ""pam_unix.so"" statement in the ""ACCOUNT"" section:



account required pam_faillock.so



Note that any updates made to ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" may be overwritten by the ""authconfig"" program.  The ""authconfig"" program should not be used.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000044

The information system enforces the organization-defined limit of consecutive invalid logon attempts by a user during the organization-defined time period.

NIST SP 800-53 :: AC-7 a

NIST SP 800-53A :: AC-7.1 (ii)

NIST SP 800-53 Revision 4 :: AC-7 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
