# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000135
#
# VULN ID
#   V-38623
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000206
#
# RULE ID
#   SV-50424r2_rule
#
# STIG ID
#   RHEL-06-000135
#
# RULE TITLE
#   All rsyslog-generated log files must have mode 0600 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000135;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38623';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000206';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50424r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000135';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'All rsyslog-generated log files must have mode 0600 or less permissive.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Log files can contain valuable information regarding system configuration. If the system log files are not protected, unauthorized users could change the logged data, eliminating their forensic value.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in ""/etc/rsyslog.conf"" and typically all appear in ""/var/log"". For each log file [LOGFILE] referenced in ""/etc/rsyslog.conf"", run the following command to inspect the file's permissions:



$ ls -l [LOGFILE]



The permissions should be 600, or more restrictive. Some log files referenced in /etc/rsyslog.conf may be created by other programs and may require exclusion from consideration.



If the permissions are not correct, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The file permissions for all log files written by rsyslog should be set to 600, or more restrictive. These log files are determined by the second part of each Rule line in ""/etc/rsyslog.conf"" and typically all appear in ""/var/log"". For each log file [LOGFILE] referenced in ""/etc/rsyslog.conf"", run the following command to inspect the file's permissions:



$ ls -l [LOGFILE]



If the permissions are not 600 or more restrictive, run the following command to correct this:



# chmod 0600 [LOGFILE]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001314

The information system reveals error messages only to organization-defined personnel or roles.

NIST SP 800-53 :: SI-11 c

NIST SP 800-53A :: SI-11.1 (iv)

NIST SP 800-53 Revision 4 :: SI-11 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
