# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000339
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

package Redhat::6::000339;

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
    return 'V-38702';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000037';
}

sub get_rule_id {
    return 'SV-50503r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000339';
}

sub get_rule_title {
    return 'The FTP daemon must be configured for logging or verbose mode.';
}

sub get_discussion {
    return <<'DISCUSSION';
To trace malicious activity facilitated by the FTP service, it must be configured to ensure that all commands sent to the ftp server are logged using the verbose vsftpd log format. The default vsftpd log file is /var/log/vsftpd.log.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Find if logging is applied to the ftp daemon.



Procedures:



If vsftpd is started by xinetd the following command will indicate the xinetd.d startup file.



# grep vsftpd /etc/xinetd.d/*







# grep server_args [vsftpd xinetd.d startup file]



This will indicate the vsftpd config file used when starting through xinetd. If the [server_args]line is missing or does not include the vsftpd configuration file, then the default config file (/etc/vsftpd/vsftpd.conf) is used.



# grep xferlog_enable [vsftpd config file]





If xferlog_enable is missing, or is not set to yes, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Add or correct the following configuration options within the ""vsftpd"" configuration file, located at ""/etc/vsftpd/vsftpd.conf"".



xferlog_enable=YES

xferlog_std_format=NO

log_ftp_protocol=YES
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000130

The information system generates audit records containing information that establishes what type of event occurred.

NIST SP 800-53 :: AU-3

NIST SP 800-53A :: AU-3.1

NIST SP 800-53 Revision 4 :: AU-3




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
