# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010090
#
# VULN ID
#   V-71897
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029-GPOS-00010
#
# RULE ID
#   SV-86521r1_rule
#
# STIG ID
#   RHEL-07-010090
#
# RULE TITLE
#   The operating system must have the screen package installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010090;

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
    return 'V-71897';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000029-GPOS-00010';
}

sub get_rule_id {
    return 'SV-86521r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010090';
}

sub get_rule_title {
    return 'The operating system must have the screen package installed.';
}

sub get_discussion {
    return <<'DISCUSSION';
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.



The screen package allows for a session lock to be implemented and configured.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system has the screen package installed.



Check to see if the screen package is installed with the following command:



# yum list installed | grep screen

screen-4.3.1-3-x86_64.rpm



If is not installed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Install the screen package to allow the initiation a session lock after a 15-minute period of inactivity for graphical users interfaces.



Install the screen program (if it is not on the system) with the following command:



# yum install screen



The console can now be locked with the following key combination:



ctrl+A x
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
