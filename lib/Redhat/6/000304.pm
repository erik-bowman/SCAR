# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000304
#
# VULN ID
#   V-38698
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000232
#
# RULE ID
#   SV-50499r2_rule
#
# STIG ID
#   RHEL-06-000304
#
# RULE TITLE
#   The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000304;

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
    return 'V-38698';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000232';
}

sub get_rule_id {
    return 'SV-50499r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000304';
}

sub get_rule_title {
    return
        'The operating system must employ automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.';
}

sub get_discussion {
    return <<'DISCUSSION';
By default, AIDE does not install itself for periodic execution. Periodically running AIDE may reveal unexpected changes in installed files.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine that periodic AIDE execution has been scheduled, run the following command:



# grep aide /etc/crontab /etc/cron.*/*



If there is no output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
AIDE should be executed on a periodic basis to check for changes. To implement a daily execution of AIDE at 4:05am using cron, add the following line to /etc/crontab:



05 4 * * * root /usr/sbin/aide --check



AIDE can be executed periodically through other means; this is merely one example.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001069

The organization employs automated mechanisms to detect the presence of unauthorized software on organizational information systems and notify designated organizational officials in accordance with the organization defined frequency.

NIST SP 800-53 :: RA-5 (7)

NIST SP 800-53A :: RA-5 (7).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
