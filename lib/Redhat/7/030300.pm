# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::030300
#
# VULN ID
#   V-72083
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000342-GPOS-00133
#
# RULE ID
#   SV-86707r1_rule
#
# STIG ID
#   RHEL-07-030300
#
# RULE TITLE
#   The operating system must off-load audit records onto a different system or media from the system being audited.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::030300;

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
    return 'V-72083';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000342-GPOS-00133';
}

sub get_rule_id {
    return 'SV-86707r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-030300';
}

sub get_rule_title {
    return
        'The operating system must off-load audit records onto a different system or media from the system being audited.';
}

sub get_discussion {
    return <<'DISCUSSION';
Information stored in one location is vulnerable to accidental or incidental deletion or alteration.



Off-loading is a common process in information systems with limited audit storage capacity.



Satisfies: SRG-OS-000342-GPOS-00133, SRG-OS-000479-GPOS-00224
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system off-loads audit records onto a different system or media from the system being audited.



To determine the remote server that the records are being sent to, use the following command:



# grep -i remote_server /etc/audisp/audisp-remote.conf

remote_server = 10.0.21.1



If a remote server is not configured, or the line is commented out, ask the System Administrator to indicate how the audit logs are off-loaded to a different system or media.



If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to off-load audit records onto a different system or media from the system being audited.



Set the remote server option in ""/etc/audisp/audisp-remote.conf"" with the IP address of the log aggregation server.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001851

The information system off-loads audit records per organization-defined frequency onto a different system or media than the system being audited.

NIST SP 800-53 Revision 4 :: AU-4 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
