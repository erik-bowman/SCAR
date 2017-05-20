# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000273
#
# VULN ID
#   V-38657
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50458r2_rule
#
# STIG ID
#   RHEL-06-000273
#
# RULE TITLE
#   The system must use SMB client signing for connecting to samba servers using mount.cifs.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000273;

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
    return 'V-38657';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50458r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000273';
}

sub get_rule_title {
    return
        'The system must use SMB client signing for connecting to samba servers using mount.cifs.';
}

sub get_discussion {
    return <<'DISCUSSION';
Packet signing can prevent man-in-the-middle attacks which modify SMB packets in transit.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If Samba is not in use, this is not applicable.



To verify that Samba clients using mount.cifs must use packet signing, run the following command:



# grep sec /etc/fstab /etc/mtab



The output should show either ""krb5i"" or ""ntlmv2i"" in use.

If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Require packet signing of clients who mount Samba shares using the ""mount.cifs"" program (e.g., those who specify shares in ""/etc/fstab""). To do so, ensure signing options (either ""sec=krb5i"" or ""sec=ntlmv2i"") are used.



See the ""mount.cifs(8)"" man page for more information. A Samba client should only communicate with servers who can support SMB packet signing.
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
