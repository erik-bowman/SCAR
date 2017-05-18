#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_030873
#
# VULN ID
#   V-73171
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000004-GPOS-00004
#
# RULE ID
#   SV-87823r2_rule
#
# STIG ID
#   RHEL-07-030873
#
# RULE TITLE
#   The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_030873;

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
    $self->{VULN_ID} = 'V-73171';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000004-GPOS-00004';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-87823r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-030873';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.



Audit records can be generated from various components within the information system (e.g., module or policy filter).
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.



Check the auditing rules in ""/etc/audit/audit.rules"" with the following command:



# grep /etc/shadow /etc/audit/audit.rules



-w /etc/shadow -p wa -k audit_rules_usergroup_modification



If the command does not return a line, or the line is commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.



Add or update the following file system rule in ""/etc/audit/rules.d/audit.rules"":



-w /etc/shadow -p wa -k identity



The audit daemon must be restarted for the changes to take effect.
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000018

The information system automatically audits account creation actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)



CCI-000172

The information system generates audit records for the events defined in AU-2 d with the content defined in AU-3.

NIST SP 800-53 :: AU-12 c

NIST SP 800-53A :: AU-12.1 (iv)

NIST SP 800-53 Revision 4 :: AU-12 c



CCI-001403

The information system automatically audits account modification actions.

NIST SP 800-53 :: AC-2 (4)

NIST SP 800-53A :: AC-2 (4).1 (i&ii)

NIST SP 800-53 Revision 4 :: AC-2 (4)



CCI-002130

The information system automatically audits account enabling actions.

NIST SP 800-53 Revision 4 :: AC-2 (4)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
