# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020300
#
# VULN ID
#   V-72003
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000104-GPOS-00051
#
# RULE ID
#   SV-86627r1_rule
#
# STIG ID
#   RHEL-07-020300
#
# RULE TITLE
#   All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020300;

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
    return 'V-72003';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000104-GPOS-00051';
}

sub get_rule_id {
    return 'SV-86627r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020300';
}

sub get_rule_title {
    return
        'All Group Identifiers (GIDs) referenced in the /etc/passwd file must be defined in the /etc/group file.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a user is assigned the GID of a group not existing on the system, and a group with the GID is subsequently created, the user may have unintended rights to any files associated with the group.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all GIDs referenced in the ""/etc/passwd"" file are defined in the ""/etc/group"" file.



Check that all referenced GIDs exist with the following command:



# pwck -r



If GIDs referenced in ""/etc/passwd"" file are returned as not defined in ""/etc/group"" file, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system to define all GIDs found in the ""/etc/passwd"" file by modifying the ""/etc/group"" file to add any non-existent group referenced in the ""/etc/passwd"" file, or change the GIDs referenced in the ""/etc/passwd"" file to a group that exists in ""/etc/group"".
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000764

The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).

NIST SP 800-53 :: IA-2

NIST SP 800-53A :: IA-2.1

NIST SP 800-53 Revision 4 :: IA-2




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
