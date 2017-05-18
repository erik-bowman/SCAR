#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000136
#
# VULN ID
#   V-38520
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000215
#
# RULE ID
#   SV-50321r1_rule
#
# STIG ID
#   RHEL-06-000136
#
# RULE TITLE
#   The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000136;

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
    $self->{VULN_ID} = 'V-38520';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000215';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50321r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000136';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To ensure logs are sent to a remote host, examine the file ""/etc/rsyslog.conf"". If using UDP, a line similar to the following should be present:



*.* @[loghost.example.com]



If using TCP, a line similar to the following should be present:



*.* @@[loghost.example.com]



If using RELP, a line similar to the following should be present:



*.* :omrelp:[loghost.example.com]





If none of these are present, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To configure rsyslog to send logs to a remote log server, open ""/etc/rsyslog.conf"" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting ""[loghost.example.com]"" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments.

To use UDP for log message delivery:



*.* @[loghost.example.com]





To use TCP for log message delivery:



*.* @@[loghost.example.com]





To use RELP for log message delivery:



*.* :omrelp:[loghost.example.com]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001348

The information system backs up audit records on an organization-defined frequency onto a different system or system component than the system or component being audited.

NIST SP 800-53 :: AU-9 (2)

NIST SP 800-53A :: AU-9 (2).1 (iii)

NIST SP 800-53 Revision 4 :: AU-9 (2)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
