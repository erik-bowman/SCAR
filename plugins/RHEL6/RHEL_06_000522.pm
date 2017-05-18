#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000522
#
# VULN ID
#   V-38445
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000057
#
# RULE ID
#   SV-50245r2_rule
#
# STIG ID
#   RHEL-06-000522
#
# RULE TITLE
#   Audit log files must be group-owned by root.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000522;

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
    $self->{VULN_ID} = 'V-38445';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000057';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50245r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000522';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'Audit log files must be group-owned by root.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
If non-privileged users can write to audit logs, audit trails can be modified or destroyed.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to check the group owner of the system audit logs:



grep ""^log_file"" /etc/audit/auditd.conf|sed s/^[^\/]*//|xargs stat -c %G:%n



Audit logs must be group-owned by root.

If they are not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Change the group owner of the audit log files with the following command:



# chgrp root [audit_file]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000162

The information system protects audit information from unauthorized access.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
