#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020700
#
# VULN ID
#   V-72031
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86655r2_rule
#
# STIG ID
#   RHEL-07-020700
#
# RULE TITLE
#   Local initialization files for local interactive users must be group-owned by the users primary group or root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020700;

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
    $self->{VULN_ID} = 'V-72031';
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
    $self->{RULE_ID} = 'SV-86655r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020700';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Local initialization files for local interactive users must be group-owned by the users primary group or root.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the local initialization files of all local interactive users are group-owned by that user’s primary Group Identifier (GID).



Check the home directory assignment for all non-privileged users on the system with the following command:



Note: The example will be for the smithj user, who has a home directory of ""/home/smithj"" and a primary group of ""users"".



# cut -d: -f 1,4,6 /etc/passwd | egrep "":[1-4][0-9]{3}""

smithj:1000:/home/smithj



# grep 1000 /etc/group

users:x:1000:smithj,jonesj,jacksons



Note: This may miss interactive users that have been assigned a privileged User Identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system logon information.



Check the group owner of all local interactive users’ initialization files with the following command:



# ls -al /home/smithj/.*

-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile

-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login

-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something



If all local interactive users’ initialization files are not group-owned by that user’s primary GID, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Change the group owner of a local interactive user’s files to the group found in ""/etc/passwd"" for the user. To change the group owner of a local interactive user home directory, use the following command:



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"", and has a primary group of users.



# chgrp users /home/smithj/<file>
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
