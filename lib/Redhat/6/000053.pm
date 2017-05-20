# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000053
#
# VULN ID
#   V-38479
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000076
#
# RULE ID
#   SV-50279r1_rule
#
# STIG ID
#   RHEL-06-000053
#
# RULE TITLE
#   User passwords must be changed at least every 60 days.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000053;

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
    return 'V-38479';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000076';
}

sub get_rule_id {
    return 'SV-50279r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000053';
}

sub get_rule_title {
    return 'User passwords must be changed at least every 60 days.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the password maximum age ensures users are required to periodically change their passwords. This could possibly decrease the utility of a stolen password. Requiring shorter password lifetimes increases the risk of users writing down the password in a convenient location subject to physical compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the maximum password age, run the command:



$ grep PASS_MAX_DAYS /etc/login.defs



The DoD requirement is 60.

If it is not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify password maximum age for new accounts, edit the file ""/etc/login.defs"" and add or correct the following line, replacing [DAYS] appropriately:



PASS_MAX_DAYS [DAYS]



The DoD requirement is 60.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000199

The information system enforces maximum password lifetime restrictions.

NIST SP 800-53 :: IA-5 (1) (d)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (d)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
