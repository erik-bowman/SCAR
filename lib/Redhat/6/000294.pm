# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000294
#
# VULN ID
#   V-38681
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50482r2_rule
#
# STIG ID
#   RHEL-06-000294
#
# RULE TITLE
#   All GIDs referenced in /etc/passwd must be defined in /etc/group
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000294;

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
    return 'V-38681';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50482r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000294';
}

sub get_rule_title {
    return 'All GIDs referenced in /etc/passwd must be defined in /etc/group';
}

sub get_discussion {
    return <<'DISCUSSION';
Inconsistency in GIDs between /etc/passwd and /etc/group could lead to a user having unintended rights.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure all GIDs referenced in /etc/passwd are defined in /etc/group, run the following command:



# pwck -r | grep 'no group'



There should be no output.

If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add a group to the system for each GID referenced without a corresponding group.
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
