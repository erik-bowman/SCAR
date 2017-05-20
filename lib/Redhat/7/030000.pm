# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030000
#
# VULN ID
#   V-72079
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000038-GPOS-00016
#
# RULE ID
#   SV-86703r1_rule
#
# STIG ID
#   RHEL-07-030000
#
# RULE TITLE
#   Auditing must be configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events.
#   These audit records must also identify individual identities of group account users.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030000;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar;
use Scar::Util::Log;
use Scar::Util::Backup;

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

sub _set_finding_status {
    my ( $self, $finding_status ) = @_;
    $self->{finding_status} = $finding_status;
    return $self->{finding_status};
}

sub get_finding_status {
    my ($self) = @_;
    return defined $self->{finding_status} ? $self->{finding_status} : undef;
}

sub get_vuln_id {
    return 'V-72079';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000038-GPOS-00016';
}

sub get_rule_id {
    return 'SV-86703r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-030000';
}

sub get_rule_title {
    return
        'Auditing must be configured to produce records containing information to establish what type of events occurred, where the events occurred, the source of the events, and the outcome of the events. These audit records must also identify individual identities of group account users.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without establishing what type of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.



Audit record content that may be necessary to satisfy this requirement includes, for example, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.



Associating event types with detected events in the operating system audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured operating system.



Satisfies: SRG-OS-000038-GPOS-00016, SRG-OS-000039-GPOS-00017, SRG-OS-000042-GPOS-00021, SRG-OS-000254-GPOS-00095, SRG-OS-000255-GPOS-00096
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system produces audit records containing information to establish when (date and time) the events occurred.



Check to see if auditing is active by issuing the following command:



# systemctl is-active auditd.service

Active: active (running) since Tue 2015-01-27 19:41:23 EST; 22h ago



If the ""auditd"" status is not active, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to produce audit records containing information to establish when (date and time) the events occurred.



Enable the auditd service with the following command:



# chkconfig auditd on
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000126

The organization determines that the organization-defined subset of the auditable events defined in AU-2 are to be audited within the information system.

NIST SP 800-53 :: AU-2 d

NIST SP 800-53A :: AU-2.1 (v)

NIST SP 800-53 Revision 4 :: AU-2 d



CCI-000131

The information system generates audit records containing information that establishes when an event occurred.

NIST SP 800-53 :: AU-3

NIST SP 800-53A :: AU-3.1

NIST SP 800-53 Revision 4 :: AU-3




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
