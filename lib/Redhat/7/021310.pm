# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021310
#
# VULN ID
#   V-72059
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86683r1_rule
#
# STIG ID
#   RHEL-07-021310
#
# RULE TITLE
#   A separate file system must be used for user home directories (such as /home or an equivalent).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021310;

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
    return 'V-72059';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86683r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021310';
}

sub get_rule_title {
    return
        'A separate file system must be used for user home directories (such as /home or an equivalent).';
}

sub get_discussion {
    return <<'DISCUSSION';
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that a separate file system/partition has been created for non-privileged local interactive user home directories.



Check the home directory assignment for all non-privileged users (those with a UID greater than 1000) on the system with the following command:



#cut -d: -f 1,3,6,7 /etc/passwd | egrep "":[1-4][0-9]{3}"" | tr "":"" ""\t""



adamsj /home/adamsj /bin/bash

jacksonm /home/jacksonm /bin/bash

smithj /home/smithj /bin/bash



The output of the command will give the directory/partition that contains the home directories for the non-privileged users on the system (in this example, /home) and users’ shell. All accounts with a valid shell (such as /bin/bash) are considered interactive users.



Check that a file system/partition has been created for the non-privileged interactive users with the following command:



Note: The partition of /home is used in the example.



# grep /home /etc/fstab

UUID=333ada18    /home                   ext4    noatime,nobarrier,nodev  1 2



If a separate entry for the file system/partition that contains the non-privileged interactive users' home directories does not exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Migrate the ""/home"" directory onto a separate file system/partition.
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
