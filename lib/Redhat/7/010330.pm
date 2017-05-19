# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010330
#
# VULN ID
#   V-71945
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000329-GPOS-00128
#
# RULE ID
#   SV-86569r1_rule
#
# STIG ID
#   RHEL-07-010330
#
# RULE TITLE
#   If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010330;

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
    $self->{VULN_ID} = 'V-71945';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000329-GPOS-00128';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86569r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010330';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'If three unsuccessful root logon attempts within 15 minutes occur the associated account must be locked.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Limits are imposed by locking the account.



Satisfies: SRG-OS-000329-GPOS-00128, SRG-OS-000021-GPOS-00005
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system automatically locks the root account until it is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.



# grep pam_faillock.so /etc/pam.d/password-auth-ac

auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900

auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900



If the ""even_deny_root"" setting is not defined on both lines with the ""pam_faillock.so"" module name, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to automatically lock the root account until the locked account is released by an administrator when three unsuccessful logon attempts in 15 minutes are made.



Modify the first three lines of the auth section of the ""/etc/pam.d/system-auth-ac"" and ""/etc/pam.d/password-auth-ac"" files to match the following lines:



auth        required       pam_faillock.so preauth silent audit deny=3 even_deny_root fail_interval=900 unlock_time=604800

auth        sufficient     pam_unix.so try_first_pass

auth        [default=die]  pam_faillock.so authfail audit deny=3 even_deny_root fail_interval=900 unlock_time=604800



and run the ""authconfig"" command.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002238

The information system automatically locks the account or node for either an organization-defined time period, until the locked account or node is released by an administrator, or delays the next login prompt according to the organization-defined delay algorithm when the maximum number of unsuccessful attempts is exceeded.

NIST SP 800-53 Revision 4 :: AC-7 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
