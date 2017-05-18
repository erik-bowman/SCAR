#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000529
#
# VULN ID
#   V-58901
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373
#
# RULE ID
#   SV-73331r1_rule
#
# STIG ID
#   RHEL-06-000529
#
# RULE TITLE
#   The sudo command must require authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000529;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-58901';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000373';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-73331r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000529';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'The sudo command must require authentication.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The ""sudo"" command allows authorized users to run programs (including shells) as other users, system users, and root. The ""/etc/sudoers"" file is used to configure authorized ""sudo"" users as well as the programs they are allowed to run. Some configuration options in the ""/etc/sudoers"" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify neither the ""NOPASSWD"" option nor the ""!authenticate"" option is configured for use in ""/etc/sudoers"" and associated files. Note that the ""#include"" and ""#includedir"" directives may be used to include configuration data from locations other than the defaults enumerated here.



# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*

# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*



If the ""NOPASSWD"" or ""!authenticate"" options are configured for use in ""/etc/sudoers"" or associated files, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Update the ""/etc/sudoers"" or other sudo configuration files to remove or comment out lines utilizing the ""NOPASSWD"" and ""!authenticate"" options.



# visudo

# visudo -f [other sudo configuration file]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002038

The organization requires users to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

NIST SP 800-53 Revision 4 :: IA-11




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
