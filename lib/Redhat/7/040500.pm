# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040500
#
# VULN ID
#   V-72269
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000355-GPOS-00143
#
# RULE ID
#   SV-86893r2_rule
#
# STIG ID
#   RHEL-07-040500
#
# RULE TITLE
#   The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040500;

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
    return 'V-72269';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000355-GPOS-00143';
}

sub get_rule_id {
    return 'SV-86893r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040500';
}

sub get_rule_title {
    return
        'The operating system must, for networked systems, synchronize clocks with a server that is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).';
}

sub get_discussion {
    return <<'DISCUSSION';
Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.



Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.



Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).



Satisfies: SRG-OS-000355-GPOS-00143, SRG-OS-000356-GPOS-00144
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Check to see if NTP is running in continuous mode.



# ps -ef | grep ntp



If NTP is not running, this is a finding.



If the process is found, then check the ""ntp.conf"" file for the ""maxpoll"" option setting:



# grep maxpoll /etc/ntp.conf



maxpoll 17



If the option is set to ""17"" or is not set, this is a finding.



If the file does not exist, check the ""/etc/cron.daily"" subdirectory for a crontab file controlling the execution of the ""ntpdate"" command.



# grep -l ntpdate /etc/cron.daily



# ls -al /etc/cron.* | grep aide

ntp



If a crontab file does not exist in the ""/etc/cron.daily"" that executes the ""ntpdate"" file, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit the ""/etc/ntp.conf"" file and add or update an entry to define ""maxpoll"" to ""10"" as follows:



maxpoll 10



If NTP was running and ""maxpoll"" was updated, the NTP service must be restarted:



# systemctl restart ntpd



If NTP was not running, it must be started:



# systemctl start ntpd
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001891

The information system compares internal information system clocks on an organization-defined frequency with an organization-defined authoritative time source.

NIST SP 800-53 Revision 4 :: AU-8 (1) (a)



CCI-002046

The information system synchronizes the internal system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.

NIST SP 800-53 Revision 4 :: AU-8 (1) (b)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
