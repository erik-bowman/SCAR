# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010230
#
# VULN ID
#   V-71925
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000075-GPOS-00043
#
# RULE ID
#   SV-86549r1_rule
#
# STIG ID
#   RHEL-07-010230
#
# RULE TITLE
#   Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010230;

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
    return 'V-71925';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000075-GPOS-00043';
}

sub get_rule_id {
    return 'SV-86549r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010230';
}

sub get_rule_title {
    return
        'Passwords for new users must be restricted to a 24 hours/1 day minimum lifetime.';
}

sub get_discussion {
    return <<'DISCUSSION';
Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enforces 24 hours/1 day as the minimum password lifetime for new user accounts.



Check for the value of ""PASS_MIN_DAYS"" in ""/etc/login.defs"" with the following command:



# grep -i pass_min_days /etc/login.defs

PASS_MIN_DAYS     1



If the ""PASS_MIN_DAYS"" parameter value is not ""1"" or greater, or is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to enforce 24 hours/1 day as the minimum password lifetime.



Add the following line in ""/etc/login.defs"" (or modify the line to have the required value):



PASS_MIN_DAYS     1
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000198

The information system enforces minimum password lifetime restrictions.

NIST SP 800-53 :: IA-5 (1) (d)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (d)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
