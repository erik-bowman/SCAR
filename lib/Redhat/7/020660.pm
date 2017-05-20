# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020660
#
# VULN ID
#   V-72023
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86647r1_rule
#
# STIG ID
#   RHEL-07-020660
#
# RULE TITLE
#   All files and directories contained in local interactive user home directories must be owned by the owner of the home directory.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020660;

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
    return 'V-72023';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86647r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020660';
}

sub get_rule_title {
    return
        'All files and directories contained in local interactive user home directories must be owned by the owner of the home directory.';
}

sub get_discussion {
    return <<'DISCUSSION';
If local interactive users do not own the files in their directories, unauthorized users may be able to access them. Additionally, if files are not owned by the user, this could be an indication of system compromise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all files and directories in a local interactive user’s home directory are owned by the user.



Check the owner of all files and directories in a local interactive user’s home directory with the following command:



Note: The example will be for the user ""smithj"", who has a home directory of ""/home/smithj"".



# ls -lLR /home/smithj

-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1

-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2

-rw-r--r-- 1 smithj smithj 231 Mar  5 17:06 file3



If any files are found with an owner different than the home directory user, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the owner of a local interactive user’s files and directories to that owner. To change the owner of a local interactive user’s files and directories, use the following command:



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"".



# chown smithj /home/smithj/<file or directory>
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
