# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000348
#
# VULN ID
#   V-38599
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000023
#
# RULE ID
#   SV-50400r2_rule
#
# STIG ID
#   RHEL-06-000348
#
# RULE TITLE
#   The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000348;

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
    return 'V-38599';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000023';
}

sub get_rule_id {
    return 'SV-50400r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000348';
}

sub get_rule_title {
    return
        'The FTPS/FTP service on the system must be configured with the Department of Defense (DoD) login banner.';
}

sub get_discussion {
    return <<'DISCUSSION';
This setting will cause the system greeting banner to be used for FTP connections as well.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify this configuration, run the following command:



grep ""banner_file"" /etc/vsftpd/vsftpd.conf



The output should show the value of ""banner_file"" is set to ""/etc/issue"", an example of which is shown below.



# grep ""banner_file"" /etc/vsftpd/vsftpd.conf

banner_file=/etc/issue





If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit the vsftpd configuration file, which resides at ""/etc/vsftpd/vsftpd.conf"" by default. Add or correct the following configuration options.



banner_file=/etc/issue



Restart the vsftpd daemon.



# service vsftpd restart
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000048

The information system displays an organization-defined system use notification message or banner before granting access to the system that provides privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NIST SP 800-53 :: AC-8 a

NIST SP 800-53A :: AC-8.1 (ii)

NIST SP 800-53 Revision 4 :: AC-8 a




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
