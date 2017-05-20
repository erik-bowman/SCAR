# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000051
#
# VULN ID
#   V-38477
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000075
#
# RULE ID
#   SV-50277r1_rule
#
# STIG ID
#   RHEL-06-000051
#
# RULE TITLE
#   Users must not be able to change passwords more than once every 24 hours.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000051;

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
    return 'V-38477';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000075';
}

sub get_rule_id {
    return 'SV-50277r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000051';
}

sub get_rule_title {
    return
        'Users must not be able to change passwords more than once every 24 hours.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the minimum password age, run the command:



$ grep PASS_MIN_DAYS /etc/login.defs



The DoD requirement is 1.

If it is not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify password minimum age for new accounts, edit the file ""/etc/login.defs"" and add or correct the following line, replacing [DAYS] appropriately:



PASS_MIN_DAYS [DAYS]



A value of 1 day is considered sufficient for many environments. The DoD requirement is 1.
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
