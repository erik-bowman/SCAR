# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000272
#
# VULN ID
#   V-38656
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50457r1_rule
#
# STIG ID
#   RHEL-06-000272
#
# RULE TITLE
#   The system must use SMB client signing for connecting to samba servers using smbclient.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000272;

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
    return 'V-38656';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50457r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000272';
}

sub get_rule_title {
    return
        'The system must use SMB client signing for connecting to samba servers using smbclient.';
}

sub get_discussion {
    return <<'DISCUSSION';
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify that Samba clients running smbclient must use packet signing, run the following command:



# grep signing /etc/samba/smb.conf



The output should show:



client signing = mandatory





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To require samba clients running ""smbclient"" to use packet signing, add the following to the ""[global]"" section of the Samba configuration file in ""/etc/samba/smb.conf"":



client signing = mandatory



Requiring samba clients such as ""smbclient"" to use packet signing ensures they can only communicate with servers that support packet signing.
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
