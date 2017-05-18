#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030820
#
# VULN ID
#   V-72187
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000471-GPOS-00216
#
# RULE ID
#   SV-86811r2_rule
#
# STIG ID
#   RHEL-07-030820
#
# RULE TITLE
#   All uses of the init_module command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030820;

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
    $self->{VULN_ID} = 'V-72187';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000471-GPOS-00216';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86811r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030820';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All uses of the init_module command must be audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).



Satisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""init_module"" command occur.



Check the auditing rules in ""/etc/audit/audit.rules"" with the following command:



Note: The output lines of the command are duplicated to cover both 32-bit and 64-bit architectures. Only the line appropriate for the system architecture must be present.



# grep -i init_module /etc/audit/audit.rules



If the command does not return the following output (appropriate to the architecture), this is a finding.



-a always,exit -F arch=b32 -S init_module -k module-change



-a always,exit -F arch=b64 -S init_module -k module-change



If the command does not return any output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system generates audit records when successful/unsuccessful attempts to use the ""init_module"" command occur.



Add or update the following rules in ""/etc/audit/rules.d/audit.rules"" (removing those that do not match the CPU architecture):



-a always,exit -F arch=b32 -S init_module -k module-change



-a always,exit -F arch=b64 -S init_module -k module-change



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
