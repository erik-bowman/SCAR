# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010060
#
# VULN ID
#   V-71891
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000028-GPOS-00009
#
# RULE ID
#   SV-86515r2_rule
#
# STIG ID
#   RHEL-07-010060
#
# RULE TITLE
#   The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010060;

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
    return 'V-71891';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000028-GPOS-00009';
}

sub get_rule_id {
    return 'SV-86515r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010060';
}

sub get_rule_title {
    return
        'The operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures.';
}

sub get_discussion {
    return <<'DISCUSSION';
A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.



The session lock is implemented at the point where session activity can be determined.



Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.



Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enables a user's session lock until that user re-establishes access using established identification and authentication procedures. The screen program must be installed to lock sessions on the console.



Note: If the system does not have GNOME installed, this requirement is Not Applicable.



Check to see if the screen lock is enabled with the following command:



# grep -i lock-enabled /etc/dconf/db/local.d/00-screensaver

lock-enabled=true



If the ""lock-enabled"" setting is missing or is not set to ""true"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to enable a user's session lock until that user re-establishes access using established identification and authentication procedures.



Create a database to contain the system-wide screensaver settings (if it does not already exist) with the following command:



# touch /etc/dconf/db/local.d/00-screensaver



Edit ""org/gnome/desktop/session"" and add or update the following lines:



# Set the lock time out to 900 seconds before the session is considered idle

idle-delay=uint32 900



Edit ""org/gnome/desktop/screensaver"" and add or update the following lines:



# Set this to true to lock the screen when the screensaver activates

lock-enabled=true

# Set the lock timeout to 180 seconds after the screensaver has been activated

lock-delay=uint32 180



You must include the ""uint32"" along with the integer key values as shown.



Override the user's setting and prevent the user from changing it by editing ""/etc/dconf/db/local.d/locks/screensaver"" and adding or updating the following lines:



# Lock desktop screensaver settings

/org/gnome/desktop/session/idle-delay

/org/gnome/desktop/screensaver/lock-enabled

/org/gnome/desktop/screensaver/lock-delay



Update the system databases:



# dconf update



Users must log out and back in again before the system-wide settings take effect.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000056

The information system retains the session lock until the user reestablishes access using established identification and authentication procedures.

NIST SP 800-53 :: AC-11 b

NIST SP 800-53A :: AC-11.1 (iii)

NIST SP 800-53 Revision 4 :: AC-11 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
