#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_07_020040
#
# VULN ID
#   V-71975
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000363-GPOS-00150
#
# RULE ID
#   SV-86599r1_rule
#
# STIG ID
#   RHEL-07-020040
#
# RULE TITLE
#   Designated personnel must be notified if baseline configurations are changed in an unauthorized manner.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_07_020040;

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
    $self->{VULN_ID} = 'V-71975';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000363-GPOS-00150';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86599r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020040';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'Designated personnel must be notified if baseline configurations are changed in an unauthorized manner.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.



Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the operating system notifies designated personnel if baseline configurations are changed in an unauthorized manner.



Note: A file integrity tool other than Advanced Intrusion Detection Environment (AIDE) may be used, but the tool must be executed and notify specified individuals via email or an alert.



Check to see if AIDE is installed on the system with the following command:



# yum list installed aide



If AIDE is not installed, ask the SA how file integrity checks are performed on the system.



Check for the presence of a cron job running routinely on the system that executes AIDE to scan for changes to the system baseline. The commands used in the example will use a daily occurrence.



Check the ""/etc/cron.daily"" subdirectory for a ""crontab"" file controlling the execution of the file integrity application. For example, if AIDE is installed on the system, use the following commands:



# ls -al /etc/cron.daily | grep aide

-rwxr-xr-x  1 root root        32 Jul  1  2011 aide



AIDE does not have a configuration that will send a notification, so the cron job uses the mail application on the system to email the results of the file integrity run as in the following example:



# more /etc/cron.daily/aide

0 0 * * * /usr/sbin/aide --check | /bin/mail -s ""$HOSTNAME - Daily aide integrity check run"" root@sysname.mil



If the file integrity application does not notify designated personnel of changes, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to notify designated personnel if baseline configurations are changed in an unauthorized manner. The AIDE tool can be configured to email designated personnel through the use of the cron system.



The following example output is generic. It will set cron to run AIDE daily and to send email at the completion of the analysis.



# more /etc/cron.daily/aide

0 0 * * * /usr/sbin/aide --check | /bin/mail -s ""$HOSTNAME - Daily aide integrity check run"" root@sysname.mil
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001744

The information system implements organization-defined security responses automatically if baseline configurations are changed in an unauthorized manner.

NIST SP 800-53 Revision 4 :: CM-3 (5)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
