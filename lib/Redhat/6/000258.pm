# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000258
#
# VULN ID
#   V-38630
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029
#
# RULE ID
#   SV-50431r3_rule
#
# STIG ID
#   RHEL-06-000258
#
# RULE TITLE
#   The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000258;

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
    return 'V-38630';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000029';
}

sub get_rule_id {
    return 'SV-50431r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000258';
}

sub get_rule_title {
    return
        'The graphical desktop environment must automatically lock after 15 minutes of inactivity and the system must require user reauthentication to unlock the environment.';
}

sub get_discussion {
    return <<'DISCUSSION';
Enabling idle activation of the screen saver ensures the screensaver will be activated after the idle delay. Applications requiring continuous, real-time screen display (such as network management products) require the login session does not have administrator rights and the display station is located in a controlled-access area.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To check the screensaver mandatory use status, run the following command:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_activation_enabled



If properly configured, the output should be ""true"".



If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to activate the screensaver in the GNOME desktop after a period of inactivity:



# gconftool-2 --direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type bool \

--set /apps/gnome-screensaver/idle_activation_enabled true
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
