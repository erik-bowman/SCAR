# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000286
#
# VULN ID
#   V-38668
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50469r3_rule
#
# STIG ID
#   RHEL-06-000286
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

package Redhat::6::000286;

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
    return 'V-38668';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50469r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000286';
}

sub get_rule_title {
    return 'The x86 Ctrl-Alt-Delete key sequence must be disabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
A locally logged-in user who presses Ctrl-Alt-Delete, when at the console, can reboot the system. If accidentally pressed, as could happen in the case of mixed OS environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. In the GNOME graphical environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure the system is configured to log a message instead of rebooting the system when Ctrl-Alt-Delete is pressed, ensure the following line is in ""/etc/init/control-alt-delete.override"":



exec /usr/bin/logger -p security.info ""Ctrl-Alt-Delete pressed""



If the system is not configured to block the shutdown command when Ctrl-Alt-Delete is pressed, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
By default, the system includes the following line in ""/etc/init/control-alt-delete.conf"" to reboot the system when the Ctrl-Alt-Delete key sequence is pressed:



exec /sbin/shutdown -r now ""Ctrl-Alt-Delete pressed""





To configure the system to log a message instead of rebooting the system, add the following line to ""/etc/init/control-alt-delete.override"" to read as follows:



exec /usr/bin/logger -p security.info ""Ctrl-Alt-Delete pressed""
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
