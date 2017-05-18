#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_010350
#
# VULN ID
#   V-71949
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373-GPOS-00156
#
# RULE ID
#   SV-86573r2_rule
#
# STIG ID
#   RHEL-07-010350
#
# RULE TITLE
#   Users must re-authenticate for privilege escalation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_010350;

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
    $self->{VULN_ID} = 'V-71949';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000373-GPOS-00156';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86573r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010350';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Users must re-authenticate for privilege escalation.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without re-authentication, users may access resources or perform tasks for which they do not have authorization.



When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.



Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system requires users to reauthenticate for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i authenticate /etc/sudoers /etc/sudoers.d/*



If any line is found with a ""!authenticate"" tag, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to require users to reauthenticate for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



Remove any occurrences of ""!authenticate"" tags in the file.
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
