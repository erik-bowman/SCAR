#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030300
#
# VULN ID
#   V-72083
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-86707r1_rule
#
# STIG ID
#   RHEL-07-030300
#
# RULE TITLE
#   The operating system must off-load audit records onto a different system or media from the system being audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030300;

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
    $self->{VULN_ID} = 'V-72083';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000342-GPOS-00133';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86707r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030300';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must off-load audit records onto a different system or media from the system being audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.



Off-loading is a common process in information systems with limited audit storage capacity.



Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system off-loads audit records onto a different system or media from the system being audited.



To determine the remote server that the records are being sent to, use the following command:



# grep -i remote_server /etc/audisp/audisp-remote.conf

remote_server = 10.0.21.1



If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.



If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to off-load audit records onto a different system or media from the system being audited.



Set the remote server option in ""/etc/audisp/audisp-remote.conf"" with the IP address of the log aggregation server.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
