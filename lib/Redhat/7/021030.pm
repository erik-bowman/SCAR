# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021030
#
# VULN ID
#   V-72047
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86671r1_rule
#
# STIG ID
#   RHEL-07-021030
#
# RULE TITLE
#   All world-writable directories must be group-owned by root, sys, bin, or an application group.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021030;

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
    return 'V-72047';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86671r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021030';
}

sub get_rule_title {
    return
        'All world-writable directories must be group-owned by root, sys, bin, or an application group.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a world-writable directory has the sticky bit set and is not group-owned by a privileged Group Identifier (GID), unauthorized users may be able to modify files created by others.



The only authorized public directories are those temporary directories supplied with the system or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system and by users for temporary file storage, (e.g., /tmp), and for directories requiring global read/write access.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all world-writable directories are group-owned by root, sys, bin, or an application group.



Check the system for world-writable directories with the following command:



Note: The value after -fstype must be replaced with the filesystem type. XFS is used as an example.



# find / -perm -002 -xdev -type d -fstype xfs -exec ls -lLd {} \;

drwxrwxrwt. 2 root root 40 Aug 26 13:07 /dev/mqueue

drwxrwxrwt. 2 root root 220 Aug 26 13:23 /dev/shm

drwxrwxrwt. 14 root root 4096 Aug 26 13:29 /tmp



If any world-writable directories are not owned by root, sys, bin, or an application group associated with the directory, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the group of the world-writable directories to root with the following command:



# chgrp root <directory>
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
