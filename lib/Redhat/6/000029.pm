# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000029
#
# VULN ID
#   V-38496
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50297r3_rule
#
# STIG ID
#   RHEL-06-000029
#
# RULE TITLE
#   Default operating system accounts, other than root, must be locked.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000029;

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
    return 'V-38496';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50297r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000029';
}

sub get_rule_title {
    return
        'Default operating system accounts, other than root, must be locked.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling authentication for default system accounts makes it more difficult for attackers to make use of them to compromise a system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To obtain a listing of all users and the contents of their shadow password field, run the command:



$ awk -F: '$1 !~ /^root$/ && $2 !~ /^[!*]/ {print $1 "":"" $2}' /etc/shadow



Identify the operating system accounts from this listing. These will primarily be the accounts with UID numbers less than 500, other than root.



If any default operating system account (other than root) has a valid password hash, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Some accounts are not associated with a human user of the system, and exist to perform some administrative function. An attacker should not be able to log into these accounts.



Disable logon access to these accounts with the command:



# passwd -l [SYSACCT]
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
