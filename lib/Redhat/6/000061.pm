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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38573';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000021';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50374r4_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000061';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must disable accounts after three consecutive unsuccessful logon attempts.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Locking out user accounts after a number of incorrect attempts prevents direct password guessing attacks.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure the failed password attempt policy is configured correctly, run the following command:



# grep pam_faillock /etc/pam.d/system-auth /etc/pam.d/password-auth



The output should show ""deny=3"" for both files.

If that is not the case, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To configure the system to lock out accounts after a number of incorrect logon attempts using ""pam_faillock.so"", modify the content of both ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" as follows:



Add the following line immediately before the ""pam_unix.so"" statement in the ""AUTH"" section:



auth required pam_faillock.so preauth silent deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately after the ""pam_unix.so"" statement in the ""AUTH"" section:



auth [default=die] pam_faillock.so authfail deny=3 unlock_time=604800 fail_interval=900



Add the following line immediately before the ""pam_unix.so"" statement in the ""ACCOUNT"" section:



account required pam_faillock.so



Note that any updates made to ""/etc/pam.d/system-auth"" and ""/etc/pam.d/password-auth"" may be overwritten by the ""authconfig"" program.  The ""authconfig"" program should not be used.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000044

The information system enforces the organization-defined limit of consecutive invalid logon attempts by a user during the organization-defined time period.

NIST SP 800-53 :: AC-7 a

NIST SP 800-53A :: AC-7.1 (ii)

NIST SP 800-53 Revision 4 :: AC-7 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
