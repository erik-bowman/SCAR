# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010320
#
# VULN ID
#   V-71943
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000329-GPOS-00128
#
# RULE ID
#   SV-86567r2_rule
#
# STIG ID
#   RHEL-07-010320
#
# RULE TITLE
#   Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010320;

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
    return 'V-71943';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000329-GPOS-00128';
}

sub get_rule_id {
    return 'SV-86567r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010320';
}

sub get_rule_title {
    return
        'Accounts subject to three unsuccessful logon attempts within 15 minutes must be locked for the maximum configurable period.';
}

sub get_discussion {
    return <<'DISCUSSION';
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.



Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system automatically locks an account for the maximum period for which the system can be configured.



Check that the system locks an account for the maximum period after three unsuccessful logon attempts within a period of 15 minutes with the following command:



# grep pam_faillock.so /etc/pam.d/password-auth-ac

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root unlock_time=604800

auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root unlock_time=604800



If the ""unlock_time"" setting is greater than ""604800"" on both lines with the ""pam_faillock.so"" module name or is missing from a line, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to lock an account for the maximum period when three unsuccessful logon attempts in 15 minutes are made.



Modify the first three lines of the auth section of the ""/etc/pam.d/system-auth-ac"" and ""/etc/pam.d/password-auth-ac"" files to match the following lines:



auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800

auth        sufficient     pam_unix.so try_first_pass

auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800



and run the ""authconfig"" command.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002238

The information system automatically locks the account or node for either an organization-defined time period, until the locked account or node is released by an administrator, or delays the next login prompt according to the organization-defined delay algorithm when the maximum number of unsuccessful attempts is exceeded.

NIST SP 800-53 Revision 4 :: AC-7 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
