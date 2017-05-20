# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020600
#
# VULN ID
#   V-72011
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86635r1_rule
#
# STIG ID
#   RHEL-07-020600
#
# RULE TITLE
#   All local interactive users must have a home directory assigned in the /etc/passwd file.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020600;

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
    return 'V-72011';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86635r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020600';
}

sub get_rule_title {
    return
        'All local interactive users must have a home directory assigned in the /etc/passwd file.';
}

sub get_discussion {
    return <<'DISCUSSION';
If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify local interactive users on the system have a home directory assigned.



Check for missing local interactive user home directories with the following command:



# pwck -r

user 'lp': directory '/var/spool/lpd' does not exist

user 'news': directory '/var/spool/news' does not exist

user 'uucp': directory '/var/spool/uucp' does not exist

user 'smithj': directory '/home/smithj' does not exist



Ask the System Administrator (SA) if any users found without home directories are local interactive users. If the SA is unable to provide a response, check for users with a User Identifier (UID) of 1000 or greater with the following command:



# cut -d: -f 1,3 /etc/passwd | egrep "":[1-4][0-9]{2}$|:[0-9]{1,2}$""



If any interactive users do not have a home directory assigned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Assign home directories to all local interactive users that currently do not have a home directory assigned.
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
