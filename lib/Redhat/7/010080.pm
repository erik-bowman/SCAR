# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010080
#
# VULN ID
#   V-71895
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029-GPOS-00010
#
# RULE ID
#   SV-86519r3_rule
#
# STIG ID
#   RHEL-07-010080
#
# RULE TITLE
#   The operating system must set the idle delay setting for all connection types.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010080;

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
    return 'V-71895';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000029-GPOS-00010';
}

sub get_rule_id {
    return 'SV-86519r3_rule';
}

sub get_stig_id {
    return 'RHEL-07-010080';
}

sub get_rule_title {
    return
        'The operating system must set the idle delay setting for all connection types.';
}

sub get_discussion {
    return <<'DISCUSSION';
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.



The session lock is implemented at the point where session activity can be determined and/or controlled.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system prevents a user from overriding session lock after a 15-minute period of inactivity for graphical user interfaces. The screen program must be installed to lock sessions on the console.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Determine which profile the system database is using with the following command:

#grep system-db /etc/dconf/profile/user



system-db:local



Check for the lock delay setting with the following command:



Note: The example below is using the database ""local"" for the system, so the path is ""/etc/dconf/db/local.d"". This path must be modified if a database other than ""local"" is being used.



# grep -i idle-delay /etc/dconf/db/local.d/locks/*



/org/gnome/desktop/screensaver/idle-delay



If the command does not return a result, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to prevent a user from overriding a session lock after a 15-minute period of inactivity for graphical user interfaces.



Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:



Note: The example below is using the database ""local"" for the system, so if the system is using another database in /etc/dconf/profile/user, the file should be created under the appropriate subdirectory.



# touch /etc/dconf/db/local.d/locks/session



Add the setting to lock the screensaver idle delay:



/org/gnome/desktop/screensaver/idle-delay
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000057

The information system initiates a session lock after the organization-defined time period of inactivity.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11.1 (ii)

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
