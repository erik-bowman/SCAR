# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000248
#
# VULN ID
#   V-38621
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000056
#
# RULE ID
#   SV-50422r1_rule
#
# STIG ID
#   RHEL-06-000248
#
# RULE TITLE
#   The system clock must be synchronized to an authoritative DoD time source.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000248;

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
    return 'V-38621';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000056';
}

sub get_rule_id {
    return 'SV-50422r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000248';
}

sub get_rule_title {
    return
        'The system clock must be synchronized to an authoritative DoD time source.';
}

sub get_discussion {
    return <<'DISCUSSION';
Synchronizing with an NTP server makes it possible to collate system logs from multiple sources or correlate computer events with real time events. Using a trusted NTP server provided by your organization is recommended.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
A remote NTP server should be configured for time synchronization. To verify one is configured, open the following file.



/etc/ntp.conf



In the file, there should be a section similar to the following:



# --- OUR TIMESERVERS -----

server [ntpserver]





If this is not the case, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify a remote NTP server for time synchronization, edit the file ""/etc/ntp.conf"". Add or correct the following lines, substituting the IP or hostname of a remote NTP server for ntpserver.



server [ntpserver]



This instructs the NTP software to contact that remote server to obtain time data.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000160

The information system synchronizes internal information system clocks on an organization defined frequency with an organization defined authoritative time source.

NIST SP 800-53 :: AU-8 (1)

NIST SP 800-53A :: AU-8 (1).1 (iii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
