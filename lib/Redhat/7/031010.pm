# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::031010
#
# VULN ID
#   V-72211
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86835r1_rule
#
# STIG ID
#   RHEL-07-031010
#
# RULE TITLE
#   The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::031010;

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
    return 'V-72211';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86835r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-031010';
}

sub get_rule_title {
    return
        'The rsyslog daemon must not accept log messages from other servers unless the server is being used for log aggregation.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unintentionally running a rsyslog server accepting remote messages puts the system at increased risk. Malicious rsyslog messages sent to the server could exploit vulnerabilities in the server software itself, could introduce misleading information in to the system's logs, or could fill the system's storage leading to a Denial of Service.

If the system is intended to be a log aggregation server its use must be documented with the ISSO.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that the system is not accepting ""rsyslog"" messages from other systems unless it is documented as a log aggregation server.



Check the configuration of ""rsyslog"" with the following command:



# grep imtcp /etc/rsyslog.conf

ModLoad imtcp



If the ""imtcp"" module is being loaded in the ""/etc/rsyslog.conf"" file, ask to see the documentation for the system being used for log aggregation.



If the documentation does not exist, or does not specify the server as a log aggregation system, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Modify the ""/etc/rsyslog.conf"" file to remove the ""ModLoad imtcp"" configuration line, or document the system as being used for log aggregation.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000318

The organization audits and reviews activities associated with configuration controlled changes to the system.

NIST SP 800-53 :: CM-3 e

NIST SP 800-53A :: CM-3.1 (v)

NIST SP 800-53 Revision 4 :: CM-3 f



CCI-000368

The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.

NIST SP 800-53 :: CM-6 c

NIST SP 800-53A :: CM-6.1 (v)

NIST SP 800-53 Revision 4 :: CM-6 c



CCI-001812

The information system prohibits user installation of software without explicit privileged status.

NIST SP 800-53 Revision 4 :: CM-11 (2)



CCI-001813

The information system enforces access restrictions.

NIST SP 800-53 Revision 4 :: CM-5 (1)



CCI-001814

The Information system supports auditing of the enforcement actions.

NIST SP 800-53 Revision 4 :: CM-5 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
