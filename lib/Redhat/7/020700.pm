# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020700
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

package Redhat::7::020700;

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
    return 'V-72031';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86655r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020700';
}

sub get_rule_title {
    return
        'Local initialization files for local interactive users must be group-owned by the users primary group or root.';
}

sub get_discussion {
    return <<'DISCUSSION';
Local initialization files for interactive users are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
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
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the group owner of a local interactive user’s files to the group found in ""/etc/passwd"" for the user. To change the group owner of a local interactive user home directory, use the following command:



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"", and has a primary group of users.



# chgrp users /home/smithj/<file>
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
