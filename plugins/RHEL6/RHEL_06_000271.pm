#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000271
#
# VULN ID
#   V-38655
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000035
#
# RULE ID
#   SV-50456r1_rule
#
# STIG ID
#   RHEL-06-000271
#
# RULE TITLE
#   The noexec option must be added to removable media partitions.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000271;

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
    $self->{VULN_ID} = 'V-38655';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000035';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50456r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000271';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The noexec option must be added to removable media partitions.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Allowing users to execute binaries from removable media such as USB keys exposes the system to potential compromise.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To verify that binaries cannot be directly executed from removable media, run the following command:



# grep noexec /etc/fstab



The output should show ""noexec"" in use.

If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The ""noexec"" mount option prevents the direct execution of binaries on the mounted filesystem. Users should not be allowed to execute binaries that exist on partitions mounted from removable media (such as a USB key). The ""noexec"" option prevents code from being executed directly from the media itself, and may therefore provide a line of defense against certain types of worms or malicious code. Add the ""noexec"" option to the fourth column of ""/etc/fstab"" for the line which controls mounting of any removable media partitions.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000087

The organization disables information system functionality that provides the capability for automatic execution of code on mobile devices without user direction.

NIST SP 800-53 :: AC-19 e

NIST SP 800-53A :: AC-19.1 (v)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
