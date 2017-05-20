# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020030
#
# VULN ID
#   V-71973
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000363-GPOS-00150
#
# RULE ID
#   SV-86597r1_rule
#
# STIG ID
#   RHEL-07-020030
#
# RULE TITLE
#   A file integrity tool must verify the baseline operating system configuration at least weekly.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020030;

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
    return 'V-71973';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000363-GPOS-00150';
}

sub get_rule_id {
    return 'SV-86597r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020030';
}

sub get_rule_title {
    return
        'A file integrity tool must verify the baseline operating system configuration at least weekly.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.



Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system routinely checks the baseline configuration for unauthorized changes.



Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed at least once per week.



Check to see if AIDE is installed on the system with the following command:



# yum list installed aide



If AIDE is not installed, ask the SA how file integrity checks are performed on the system.



Check for the presence of a cron job running daily or weekly on the system that executes AIDE daily to scan for changes to the system baseline. The command used in the example will use a daily occurrence.



Check the ""/etc/cron.daily"" subdirectory for a ""crontab"" file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following command:



# ls -al /etc/cron.* | grep aide

-rwxr-xr-x  1 root root        29 Nov  22  2015 aide



If the file integrity application does not exist, or a ""crontab"" file does not exist in the ""/etc/cron.daily"" or ""/etc/cron.weekly"" subdirectories, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the file integrity tool to automatically run on the system at least weekly. The following example output is generic. It will set cron to run AIDE daily, but other file integrity tools may be used:



# cat /etc/cron.daily/aide

0 0 * * * /usr/sbin/aide --check | /bin/mail -s ""aide integrity check run for <system name>"" root@sysname.mil
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001744

The information system implements organization-defined security responses automatically if baseline configurations are changed in an unauthorized manner.

NIST SP 800-53 Revision 4 :: CM-3 (5)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
