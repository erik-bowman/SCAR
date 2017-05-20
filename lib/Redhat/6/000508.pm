# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000508
#
# VULN ID
#   V-38474
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000030
#
# RULE ID
#   SV-50274r2_rule
#
# STIG ID
#   RHEL-06-000508
#
# RULE TITLE
#   The system must allow locking of graphical desktop sessions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000508;

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
    return 'V-38474';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000030';
}

sub get_rule_id {
    return 'SV-50274r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000508';
}

sub get_rule_title {
    return 'The system must allow locking of graphical desktop sessions.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ability to lock graphical desktop sessions manually allows users to easily secure their accounts should they need to depart from their workstations temporarily.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



Verify the keybindings for the Gnome screensaver:



# gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome_settings_daemon/keybindings/screensaver



If no output is visible, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to set the Gnome desktop keybinding for locking the screen:



# gconftool-2

--direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type string \

--set /apps/gnome_settings_daemon/keybindings/screensaver ""<Control><Alt>l""



Another keyboard sequence may be substituted for ""<Control><Alt>l"", which is the default for the Gnome desktop.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000058

The information system provides the capability for users to directly initiate session lock mechanisms.

NIST SP 800-53 :: AC-11 a

NIST SP 800-53A :: AC-11

NIST SP 800-53 Revision 4 :: AC-11 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
