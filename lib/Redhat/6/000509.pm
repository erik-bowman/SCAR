# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000509
#
# VULN ID
#   V-38471
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000043
#
# RULE ID
#   SV-50271r1_rule
#
# STIG ID
#   RHEL-06-000509
#
# RULE TITLE
#   The system must forward audit records to the syslog service.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000509;

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
    return 'V-38471';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000043';
}

sub get_rule_id {
    return 'SV-50271r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000509';
}

sub get_rule_title {
    return 'The system must forward audit records to the syslog service.';
}

sub get_discussion {
    return <<'DISCUSSION';
The auditd service does not include the ability to send audit records to a centralized server for management directly.  It does, however, include an audit event multiplexor plugin (audispd) to pass audit records to the local syslog server.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the audispd plugin is active:



# grep active /etc/audisp/plugins.d/syslog.conf



If the ""active"" setting is missing or set to ""no"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the ""active"" line in ""/etc/audisp/plugins.d/syslog.conf"" to ""yes"".  Restart the auditd process.



# service auditd restart
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000136

The organization centrally manages the content of audit records generated by organization defined information system components.

NIST SP 800-53 :: AU-3 (2)

NIST SP 800-53A :: AU-3 (2).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
