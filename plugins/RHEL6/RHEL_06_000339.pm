#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000339
#
# VULN ID
#   V-38702
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000037
#
# RULE ID
#   SV-50503r1_rule
#
# STIG ID
#   RHEL-06-000339
#
# RULE TITLE
#   The FTP daemon must be configured for logging or verbose mode.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000339;

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
    $self->{VULN_ID} = 'V-38702';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000037';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50503r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000339';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The FTP daemon must be configured for logging or verbose mode.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Find if logging is applied to the ftp daemon.



Procedures:



If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file.



# grep vsftpd /etc/xinetd.d/*







# grep server_args [vsftpd xinetd.d startup file]



This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used.



# grep xferlog_enable [vsftpd config file]





If xferlog_enable is missing, or is not set to yes, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Add or correct the following configuration options within the ""vsftpd"" configuration file, located at ""/etc/vsftpd/vsftpd.conf"".



xferlog_enable=YES

xferlog_std_format=NO

log_ftp_protocol=YES
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000130

The information system generates audit records containing information that establishes what type of event occurred.

NIST SP 800-53 :: AU-3

NIST SP 800-53A :: AU-3.1

NIST SP 800-53 Revision 4 :: AU-3




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
