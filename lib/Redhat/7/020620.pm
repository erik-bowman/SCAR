# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020620
#
# VULN ID
#   V-72015
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86639r1_rule
#
# STIG ID
#   RHEL-07-020620
#
# RULE TITLE
#   All local interactive user home directories defined in the /etc/passwd file must exist.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020620;

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
    return 'V-72015';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86639r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020620';
}

sub get_rule_title {
    return
        'All local interactive user home directories defined in the /etc/passwd file must exist.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a local interactive user has a home directory defined that does not exist, the user may be given access to the / directory as the current working directory upon logon. This could create a Denial of Service because the user would not be able to access their logon configuration files, and it may give them visibility to system files they normally would not be able to access.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the assigned home directory of all local interactive users on the system exists.



Check the home directory assignment for all local interactive non-privileged users on the system with the following command:



# cut -d: -f 1,3 /etc/passwd | egrep "":[1-9][0-9]{2}$|:[0-9]{1,2}$""

smithj /home/smithj



Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.



Check that all referenced home directories exist with the following command:



# pwck -r

user 'smithj': directory '/home/smithj' does not exist



If any home directories referenced in ""/etc/passwd"" are returned as not defined, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Create home directories to all local interactive users that currently do not have a home directory assigned. Use the following commands to create the user home directory assigned in ""/etc/ passwd"":



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"", a UID of ""smithj"", and a Group Identifier (GID) of ""users assigned"" in ""/etc/passwd"".



# mkdir /home/smithj

# chown smithj /home/smithj

# chgrp users /home/smithj

# chmod 0750 /home/smithj
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
