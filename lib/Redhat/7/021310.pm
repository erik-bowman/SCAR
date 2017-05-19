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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-72059';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86683r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-021310';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'A separate file system must be used for user home directories (such as /home or an equivalent).';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The use of separate file systems for different paths can protect the system from failures resulting from a file system becoming full or failing.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Migrate the ""/home"" directory onto a separate file system/partition.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
