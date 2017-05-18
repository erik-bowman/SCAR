#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000173
#
# VULN ID
#   V-38530
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000062
#
# RULE ID
#   SV-50331r2_rule
#
# STIG ID
#   RHEL-06-000173
#
# RULE TITLE
#   The audit system must be configured to audit all attempts to alter system time through /etc/localtime.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000173;

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
    $self->{VULN_ID} = 'V-38530';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000062';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50331r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000173';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The audit system must be configured to audit all attempts to alter system time through /etc/localtime.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Arbitrary changes to the system time can be used to obfuscate nefarious activities in log files, as well as to confuse network services that are highly dependent upon an accurate system time (such as sshd). All changes to the system time should be audited.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To determine if the system is configured to audit attempts to alter time via the /etc/localtime file, run the following command:



$ sudo grep -w ""/etc/localtime"" /etc/audit/audit.rules



If the system is configured to audit this activity, it will return a line.



If the system is not configured to audit time changes, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Add the following to ""/etc/audit/audit.rules"":



-w /etc/localtime -p wa -k audit_time_rules



The -k option allows for the specification of a key in string form that can be used for better reporting capability through ausearch and aureport and should always be used.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000169

The information system provides audit record generation capability for the auditable events defined in AU-2 a at organization-defined information system components.

NIST SP 800-53 :: AU-12 a

NIST SP 800-53A :: AU-12.1 (ii)

NIST SP 800-53 Revision 4 :: AU-12 a




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
