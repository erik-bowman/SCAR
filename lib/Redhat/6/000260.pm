# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000260
#
# VULN ID
#   V-38639
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000031
#
# RULE ID
#   SV-50440r3_rule
#
# STIG ID
#   RHEL-06-000260
#
# RULE TITLE
#   The system must display a publicly-viewable pattern during a graphical desktop environment session lock.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000260;

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
    return 'V-38639';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000031';
}

sub get_rule_id {
    return 'SV-50440r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000260';
}

sub get_rule_title {
    return
        'The system must display a publicly-viewable pattern during a graphical desktop environment session lock.';
}

sub get_discussion {
    return <<'DISCUSSION';
Setting the screensaver mode to blank-only conceals the contents of the display from passersby.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To ensure the screensaver is configured to be blank, run the following command:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gnome-screensaver/mode



If properly configured, the output should be ""blank-only"".

If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to set the screensaver mode in the GNOME desktop to a blank screen:



# gconftool-2 \

--direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type string \

--set /apps/gnome-screensaver/mode blank-only
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000060

The information system conceals, via the session lock, information previously visible on the display with a publicly viewable image.

NIST SP 800-53 :: AC-11 (1)

NIST SP 800-53A :: AC-11 (1).1

NIST SP 800-53 Revision 4 :: AC-11 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
