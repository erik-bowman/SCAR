# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040690
#
# VULN ID
#   V-72299
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86923r1_rule
#
# STIG ID
#   RHEL-07-040690
#
# RULE TITLE
#   A File Transfer Protocol (FTP) server package must not be installed unless needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040690;

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
    return 'V-72299';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86923r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040690';
}

sub get_rule_title {
    return
        'A File Transfer Protocol (FTP) server package must not be installed unless needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
The FTP service provides an unencrypted remote access that does not provide for the confidentiality and integrity of user passwords or the remote session. If a privileged user were to log on using this service, the privileged user password could be compromised. SSH or other encrypted file transfer methods must be used in place of this service.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify a lightweight FTP server has not been installed on the system.



Check to see if a lightweight FTP server has been installed with the following commands:



# yum list installed lftpd

 lftp-4.4.8-7.el7.x86_64.rpm



If ""lftpd"" is installed and is not documented with the Information System Security Officer (ISSO) as an operational requirement, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Document the ""lftpd"" package with the ISSO as an operational requirement or remove it from the system with the following command:



# yum remove lftpd
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
