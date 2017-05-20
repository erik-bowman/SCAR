# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010300
#
# VULN ID
#   V-71939
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000106-GPOS-00053
#
# RULE ID
#   SV-86563r2_rule
#
# STIG ID
#   RHEL-07-010300
#
# RULE TITLE
#   The SSH daemon must not allow authentication using an empty password.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010300;

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
    return 'V-71939';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000106-GPOS-00053';
}

sub get_rule_id {
    return 'SV-86563r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010300';
}

sub get_rule_title {
    return
        'The SSH daemon must not allow authentication using an empty password.';
}

sub get_discussion {
    return <<'DISCUSSION';
Configuring this setting for the SSH daemon provides additional assurance that remote logon via SSH will require a password, even in the event of misconfiguration elsewhere.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine how the SSH daemon's ""PermitEmptyPasswords"" option is set, run the following command:



# grep -i PermitEmptyPasswords /etc/ssh/sshd_config

PermitEmptyPasswords no



If no line, a commented line, or a line indicating the value ""no"" is returned, the required value is set.



If the required value is not set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To explicitly disallow remote logon from accounts with empty passwords, add or correct the following line in ""/etc/ssh/sshd_config"":



PermitEmptyPasswords no



The SSH service must be restarted for changes to take effect.  Any accounts with empty passwords should be disabled immediately, and PAM configuration should prevent users from being able to assign themselves empty passwords.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000766

The information system implements multifactor authentication for network access to non-privileged accounts.

NIST SP 800-53 :: IA-2 (2)

NIST SP 800-53A :: IA-2 (2).1

NIST SP 800-53 Revision 4 :: IA-2 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
