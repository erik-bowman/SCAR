# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010290
#
# VULN ID
#   V-71937
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86561r1_rule
#
# STIG ID
#   RHEL-07-010290
#
# RULE TITLE
#   The system must not have accounts configured with blank or null passwords.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010290;

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
    return 'V-71937';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86561r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010290';
}

sub get_rule_title {
    return
        'The system must not have accounts configured with blank or null passwords.';
}

sub get_discussion {
    return <<'DISCUSSION';
If an account has an empty password, anyone could log on and run commands with the privileges of that account. Accounts with empty passwords should never be used in operational environments.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that null passwords cannot be used, run the following command:



# grep nullok /etc/pam.d/system-auth-ac



If this produces any output, it may be possible to log on with accounts with empty passwords.



If null passwords can be used, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If an account is configured for password authentication but does not have an assigned password, it may be possible to log on to the account without authenticating.



Remove any instances of the ""nullok"" option in ""/etc/pam.d/system-auth-ac"" to prevent logons with empty passwords and run the ""authconfig"" command.
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