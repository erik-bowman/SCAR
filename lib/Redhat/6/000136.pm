# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000136
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

package Redhat::6::000136;

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
    return 'V-38520';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000215';
}

sub get_rule_id {
    return 'SV-50321r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000136';
}

sub get_rule_title {
    return
        'The operating system must back up audit records on an organization defined frequency onto a different system or media than the system being audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
A log server (loghost) receives syslog messages from one or more systems. This data can be used as an additional log source in the event a system is compromised and its local logs are suspect. Forwarding log messages to a remote loghost also provides system administrators with a centralized place to view the status of multiple hosts within the enterprise.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure logs are sent to a remote host, examine the file ""/etc/rsyslog.conf"". If using UDP, a line similar to the following should be present:



*.* @[loghost.example.com]



If using TCP, a line similar to the following should be present:



*.* @@[loghost.example.com]



If using RELP, a line similar to the following should be present:



*.* :omrelp:[loghost.example.com]





If none of these are present, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To configure rsyslog to send logs to a remote log server, open ""/etc/rsyslog.conf"" and read and understand the last section of the file, which describes the multiple directives necessary to activate remote logging. Along with these other directives, the system can be configured to forward its logs to a particular log server by adding or correcting one of the following lines, substituting ""[loghost.example.com]"" appropriately. The choice of protocol depends on the environment of the system; although TCP and RELP provide more reliable message delivery, they may not be supported in all environments.

To use UDP for log message delivery:



*.* @[loghost.example.com]





To use TCP for log message delivery:



*.* @@[loghost.example.com]





To use RELP for log message delivery:



*.* :omrelp:[loghost.example.com]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001348

The information system backs up audit records on an organization-defined frequency onto a different system or system component than the system or component being audited.

NIST SP 800-53 :: AU-9 (2)

NIST SP 800-53A :: AU-9 (2).1 (iii)

NIST SP 800-53 Revision 4 :: AU-9 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
