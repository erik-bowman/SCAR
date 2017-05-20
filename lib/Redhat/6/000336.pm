# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000336
#
# VULN ID
#   V-38697
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50498r2_rule
#
# STIG ID
#   RHEL-06-000336
#
# RULE TITLE
#   The sticky bit must be set on all public directories.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000336;

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
    return 'V-38697';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50498r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000336';
}

sub get_rule_title {
    return 'The sticky bit must be set on all public directories.';
}

sub get_discussion {
    return <<'DISCUSSION';
Failing to set the sticky bit on public directories allows unauthorized users to delete files in the directory structure.



The only authorized public directories are those temporary directories supplied with the system, or those designed to be temporary file repositories. The setting is normally reserved for directories used by the system, and by users for temporary file storage - such as /tmp - and for directories requiring global read/write access.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To find world-writable directories that lack the sticky bit, run the following command for each local partition [PART]:



# find [PART] -xdev -type d -perm -002 \! -perm -1000





If any world-writable directories are missing the sticky bit, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
When the so-called 'sticky bit' is set on a directory, only the owner of a given file may remove that file from the directory. Without the sticky bit, any user with write access to a directory may remove any file in the directory. Setting the sticky bit prevents users from removing each other's files. In cases where there is no reason for a directory to be world-writable, a better solution is to remove that permission rather than to set the sticky bit. However, if a directory is used by a particular application, consult that application's documentation instead of blindly changing modes.

To set the sticky bit on a world-writable directory [DIR], run the following command:



# chmod +t [DIR]
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
