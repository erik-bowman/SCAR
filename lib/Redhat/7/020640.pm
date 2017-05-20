# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020640
#
# VULN ID
#   V-72019
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86643r2_rule
#
# STIG ID
#   RHEL-07-020640
#
# RULE TITLE
#   All local interactive user home directories must be owned by their respective users.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020640;

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
    return 'V-72019';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86643r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020640';
}

sub get_rule_title {
    return
        'All local interactive user home directories must be owned by their respective users.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a local interactive user does not own their home directory, unauthorized users could access or modify the user's files, and the users may not be able to access their own files.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the assigned home directory of all local interactive users on the system exists.



Check the home directory assignment for all local interactive non-privileged users on the system with the following command:



Note: This may miss interactive users that have been assigned a privileged UID. Evidence of interactive use may be obtained from a number of log files containing system logon information.



# ls -ld $ (egrep ':[0-9]{4}' /etc/passwd | cut -d: -f6)

-rwxr-x--- 1 smithj users  18 Mar  5 17:06 /home/smithj



If any home directories referenced in ""/etc/passwd"" are returned as not defined, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Change the owner of a local interactive user’s home directories to that owner. To change the owner of a local interactive user’s home directory, use the following command:



Note: The example will be for the user smithj, who has a home directory of ""/home/smithj"".



# chown smithj /home/smithj
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
