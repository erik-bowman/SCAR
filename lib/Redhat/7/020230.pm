# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020230
#
# VULN ID
#   V-71993
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86617r1_rule
#
# STIG ID
#   RHEL-07-020230
#
# RULE TITLE
#   The x86 Ctrl-Alt-Delete key sequence must be disabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020230;

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
    return 'V-71993';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86617r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020230';
}

sub get_rule_title {
    return 'The x86 Ctrl-Alt-Delete key sequence must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
A locally logged-on user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of a mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system is not configured to reboot the system when Ctrl-Alt-Delete is pressed.



Check that the ctrl-alt-del.service is not active with the following command:



# systemctl status ctrl-alt-del.service

reboot.target - Reboot

   Loaded: loaded (/usr/lib/systemd/system/reboot.target; disabled)

   Active: inactive (dead)

     Docs: man:systemd.special(7)



If the ctrl-alt-del.service is active, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system to disable the Ctrl-Alt_Delete sequence for the command line with the following command:



# systemctl mask ctrl-alt-del.target



If GNOME is active on the system, create a database to contain the system-wide setting (if it does not already exist) with the following command:



# cat /etc/dconf/db/local.d/00-disable-CAD



Add the setting to disable the Ctrl-Alt_Delete sequence for GNOME:



[org/gnome/settings-daemon/plugins/media-keys]

logout=’’
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
