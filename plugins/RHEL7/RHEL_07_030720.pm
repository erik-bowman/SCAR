#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030720
#
# VULN ID
#   V-72167
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000037-GPOS-00015
#
# RULE ID
#   SV-86791r3_rule
#
# STIG ID
#   RHEL-07-030720
#
# RULE TITLE
#   All uses of the chsh command must be audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030720;

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
    $self->{VULN_ID} = 'V-72167';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000037-GPOS-00015';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86791r3_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030720';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE} = 'All uses of the chsh command must be audited.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.



At a minimum, the organization must audit the full-text recording of privileged access commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.



Satisfies: SRG-OS-000037-GPOS-00015, SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172, SRG-OS-000462-GPOS-00206, SRG-OS-000471-GPOS-00215
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system generates audit records when successful/unsuccessful attempts to use the ""chsh"" command occur.



Check for the following system call being audited by performing the following command to check the file system rules in ""/etc/audit/audit.rules"":



# grep -i /usr/bin/chsh /etc/audit/audit.rules



-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change



If the command does not return any output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to generate audit records when successful/unsuccessful attempts to use the ""chsh"" command occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"":



-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged-priv_change



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000130

The information system generates audit records containing information that establishes what type of event occurred.

NIST SP 800-53 :: AU-3

NIST SP 800-53A :: AU-3.1

NIST SP 800-53 Revision 4 :: AU-3



CCI-000135

The information system generates audit records containing the organization-defined additional, more detailed information that is to be included in the audit records.

NIST SP 800-53 :: AU-3 (1)

NIST SP 800-53A :: AU-3 (1).1 (ii)

NIST SP 800-53 Revision 4 :: AU-3 (1)



CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c



CCI-002884

The organization audits nonlocal maintenance and diagnostic sessions' organization-defined audit events.

NIST SP 800-53 Revision 4 :: MA-4 (1) (a)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
