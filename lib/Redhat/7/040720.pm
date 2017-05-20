# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040720
#
# VULN ID
#   V-72305
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86929r1_rule
#
# STIG ID
#   RHEL-07-040720
#
# RULE TITLE
#   If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040720;

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
    return 'V-72305';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86929r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040720';
}

sub get_rule_title {
    return
        'If the Trivial File Transfer Protocol (TFTP) server is required, the TFTP daemon must be configured to operate in secure mode.';
}

sub get_discussion {
    return <<'DISCUSSION';
Restricting TFTP to a specific directory prevents remote users from copying, transferring, or overwriting system files.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the TFTP daemon is configured to operate in secure mode.



Check to see if a TFTP server has been installed with the following commands:



# yum list installed | grep tftp

tftp-0.49-9.el7.x86_64.rpm



If a TFTP server is not installed, this is Not Applicable.



If a TFTP server is installed, check for the server arguments with the following command:



# grep server_arge /etc/xinetd.d/tftp

server_args = -s /var/lib/tftpboot



If the ""server_args"" line does not have a ""-s"" option and a subdirectory is not assigned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the TFTP daemon to operate in secure mode by adding the following line to ""/etc/xinetd.d/tftp"" (or modify the line to have the required value):



server_args = -s /var/lib/tftpboot
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
