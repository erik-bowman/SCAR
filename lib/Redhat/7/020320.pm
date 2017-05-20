# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020320
#
# VULN ID
#   V-72007
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86631r1_rule
#
# STIG ID
#   RHEL-07-020320
#
# RULE TITLE
#   All files and directories must have a valid owner.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020320;

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
    return 'V-72007';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86631r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020320';
}

sub get_rule_title {
    return 'All files and directories must have a valid owner.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unowned files and directories may be unintentionally inherited if a user is assigned the same User Identifier ""UID"" as the UID of the un-owned files.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all files and directories on the system have a valid owner.



Check the owner of all files and directories with the following command:



Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.



# find / -xdev -fstype xfs -nouser



If any files on the system do not have an assigned owner, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Either remove all files and directories from the system that do not have a valid user, or assign a valid user to all unowned files and directories on the system with the ""chown"" command:



# chown <user> <file>
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
