# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010260
#
# VULN ID
#   V-71931
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000076-GPOS-00044
#
# RULE ID
#   SV-86555r1_rule
#
# STIG ID
#   RHEL-07-010260
#
# RULE TITLE
#   Existing passwords must be restricted to a 60-day maximum lifetime.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010260;

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
    return 'V-71931';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000076-GPOS-00044';
}

sub get_rule_id {
    return 'SV-86555r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010260';
}

sub get_rule_title {
    return
        'Existing passwords must be restricted to a 60-day maximum lifetime.';
}

sub get_discussion {
    return <<'DISCUSSION';
Any password, no matter how complex, can eventually be cracked. Therefore, passwords need to be changed periodically. If the operating system does not limit the lifetime of passwords and force users to change their passwords, there is the risk that the operating system passwords could be compromised.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check whether the maximum time period for existing passwords is restricted to 60 days.



# awk -F: '$5 > 60 {print $1}' /etc/shadow



If any results are returned that are not associated with a system account, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure non-compliant accounts to enforce a 60-day maximum password lifetime restriction.



# chage -M 60 [user]
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
