# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000257
#
# VULN ID
#   V-38629
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000029
#
# RULE ID
#   SV-50430r3_rule
#
# STIG ID
#   RHEL-06-000257
#
# RULE TITLE
#   The graphical desktop environment must set the idle timeout to no more than 15 minutes.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000257;

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
    return 'V-38629';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000029';
}

sub get_rule_id {
    return 'SV-50430r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000257';
}

sub get_rule_title {
    return
        'The graphical desktop environment must set the idle timeout to no more than 15 minutes.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the idle delay controls when the screensaver will start, and can be combined with screen locking to prevent access from passersby.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To check the current idle time-out value, run the following command:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/idle_delay



If properly configured, the output should be ""15"".



If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to set the idle time-out value for inactivity in the GNOME desktop to 15 minutes:



# gconftool-2 \

--direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type int \

--set /apps/gnome-screensaver/idle_delay 15
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
