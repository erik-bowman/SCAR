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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38688';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000024';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50489r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000324';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'A login banner must be displayed immediately prior to, or as part of, graphical desktop environment login prompts.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
An appropriate warning message reinforces policy awareness during the logon process and facilitates possible legal action against attackers.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the GConf2 package is not installed, this is not applicable.



To ensure a login warning banner is enabled, run the following:



$ gconftool-2 --direct --config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory --get /apps/gdm/simple-greeter/banner_message_enable



Search for the ""banner_message_enable"" schema. If properly configured, the ""default"" value should be ""true"".

If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To enable displaying a login warning banner in the GNOME Display Manager's login screen, run the following command:



# gconftool-2 --direct \

--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \

--type bool \

--set /apps/gdm/simple-greeter/banner_message_enable true



To display a banner, this setting must be enabled and then banner text must also be set.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000050

The information system retains the notification message or banner on the screen until users acknowledge the usage conditions and take explicit actions to log on to or further access.

NIST SP 800-53 :: AC-8 b

NIST SP 800-53A :: AC-8.1 (iii)

NIST SP 800-53 Revision 4 :: AC-8 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
