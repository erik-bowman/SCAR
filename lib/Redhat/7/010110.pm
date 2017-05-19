# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010110
#
# VULN ID
#   V-71901
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029-GPOS-00010
#
# RULE ID
#   SV-86525r1_rule
#
# STIG ID
#   RHEL-07-010110
#
# RULE TITLE
#   The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010110;

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
    $self->{VULN_ID} = 'V-71901';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000029-GPOS-00010';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86525r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010110';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must initiate a session lock for graphical user interfaces when the screensaver is activated.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.



The session lock is implemented at the point where session activity can be determined and/or controlled.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system initiates a session lock a for graphical user interfaces when the screensaver is activated. The screen program must be installed to lock sessions on the console.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



If GNOME is installed, check to see a session lock occurs when the screensaver is activated with the following command:



# grep -i lock-delay /etc/dconf/db/local.d/*

lock-delay=uint32 5



If the ""lock-delay"" setting is missing, or is not set, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to initiate a session lock for graphical user interfaces when a screensaver is activated.



Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:



# touch /etc/dconf/db/local.d/00-screensaver



Add the setting to enable session locking when a screensaver is activated:



[org/gnome/desktop/screensaver]

lock-delay=uint32 5



After the setting has been set, run dconf update.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000057

The information system initiates a session lock after the organization-defined time period of inactivity.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11.1 (ii)

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
