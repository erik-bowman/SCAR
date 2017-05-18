#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020200
#
# VULN ID
#   V-71987
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000437-GPOS-00194
#
# RULE ID
#   SV-86611r1_rule
#
# STIG ID
#   RHEL-07-020200
#
# RULE TITLE
#   The operating system must remove all software components after updated versions have been installed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020200;

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
    $self->{VULN_ID} = 'V-71987';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000437-GPOS-00194';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86611r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020200';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must remove all software components after updated versions have been installed.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system removes all software components after updated versions have been installed.



Check if yum is configured to remove unneeded packages with the following command:



# grep -i clean_requirements_on_remove /etc/yum.conf

clean_requirements_on_remove=1



If ""clean_requirements_on_remove"" is not set to ""1"", ""True"", or ""yes"", or is not set in ""/etc/yum.conf"", this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to remove all software components after updated versions have been installed.



Set the ""clean_requirements_on_remove"" option to ""1"" in the ""/etc/yum.conf"" file:



clean_requirements_on_remove=1
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002617

The organization removes organization-defined software components (e.g., previous versions) after updated versions have been installed.

NIST SP 800-53 Revision 4 :: SI-2 (6)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
