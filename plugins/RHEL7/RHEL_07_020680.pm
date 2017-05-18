#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020680
#
# VULN ID
#   V-72027
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86651r1_rule
#
# STIG ID
#   RHEL-07-020680
#
# RULE TITLE
#   All files and directories contained in local interactive user home directories must have mode 0750 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020680;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-72027';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86651r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020680';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All files and directories contained in local interactive user home directories must have mode 0750 or less permissive.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
If a local interactive user files have excessive permissions, unintended users may be able to access or modify them.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify all files and directories contained in a local interactive user home directory, excluding local initialization files, have a mode of ""0750"".



Check the mode of all non-initialization files in a local interactive user home directory with the following command:



Files that begin with a ""."" are excluded from this requirement.



Note: The example will be for the user ""smithj"", who has a home directory of ""/home/smithj"".



# ls -lLR /home/smithj

-rwxr-x--- 1 smithj smithj  18 Mar  5 17:06 file1

-rwxr----- 1 smithj smithj 193 Mar  5 17:06 file2

-rw-r-x--- 1 smithj smithj 231 Mar  5 17:06 file3



If any files are found with a mode more permissive than ""0750"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Set the mode on files and directories in the local interactive user home directory with the following command:



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"" and is a member of the users group.



# chmod 0750 /home/smithj/<file>
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
