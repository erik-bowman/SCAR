# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000324
#
# VULN ID
#   V-38688
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000024
#
# RULE ID
#   SV-50489r3_rule
#
# STIG ID
#   RHEL-06-000324
#
# RULE TITLE
#   A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000324;

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
    return 'V-38688';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000024';
}

sub get_rule_id {
    return 'SV-50489r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000324';
}

sub get_rule_title {
    return
        'A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.';
}

sub get_discussion {
    return <<'DISCUSSION';
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To ensure a login warning banner is enabled, run the following:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable



Search for the ""banner_message_enable"" schema. If properly configured, the ""default"" value should be ""true"".

If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To enable displaying a login warning banner in the GNOME Display Manager's login screen, run the following command:



# gconftool-2 --direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type bool \

--set /apps/gdm/simple-greeter/banner_message_enable true



To display a banner, this setting must be enabled and then banner text must also be set.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000050

The information system retains the notification message or banner on the screen until users acknowledge the usage conditions and take explicit actions to log on to or further access.

NIST SP 800-53 :: AC-8 b

NIST SP 800-53A :: AC-8.1 (iii)

NIST SP 800-53 Revision 4 :: AC-8 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
