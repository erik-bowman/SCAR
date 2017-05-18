#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030610
#
# VULN ID
#   V-72145
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000392-GPOS-00172
#
# RULE ID
#   SV-86769r2_rule
#
# STIG ID
#   RHEL-07-030610
#
# RULE TITLE
#   The operating system must generate audit records for all unsuccessful account access events.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030610;

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
    $self->{VULN_ID} = 'V-72145';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000392-GPOS-00172';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86769r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030610';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must generate audit records for all unsuccessful account access events.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).



Satisfies: SRG-OS-000392-GPOS-00172, SRG-OS-000470-GPOS-00214, SRG-OS-000473-GPOS-00218
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system generates audit records when unsuccessful account access events occur.



Check the file system rule in ""/etc/audit/audit.rules"" with the following commands:



# grep -i /var/run/faillock /etc/audit/audit.rules



-w /var/run/faillock -p wa -k logins



If the command does not return any output, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to generate audit records when unsuccessful account access events occur.



Add or update the following rule in ""/etc/audit/rules.d/audit.rules"":



-w /var/run/faillock/ -p wa -k logins



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000126

The organization determines that the organization-defined subset of the auditable events defined in AU-2 are to be audited within the information system.

NIST SP 800-53 :: AU-2 d

NIST SP 800-53A :: AU-2.1 (v)

NIST SP 800-53 Revision 4 :: AU-2 d



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
