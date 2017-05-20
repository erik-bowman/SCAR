# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040410
#
# VULN ID
#   V-72255
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86879r1_rule
#
# STIG ID
#   RHEL-07-040410
#
# RULE TITLE
#   The SSH public host key files must have mode 0644 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040410;

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
    return 'V-72255';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86879r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040410';
}

sub get_rule_title {
    return
        'The SSH public host key files must have mode 0644 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH public host key files have mode ""0644"" or less permissive.



Note: SSH public key files may be found in other directories on the system depending on the installation.



The following command will find all SSH public key files on the system:



# find /etc/ssh -name '*.pub' -exec ls -lL {} \;



-rw-r--r--  1 root  wheel  618 Nov 28 06:43 ssh_host_dsa_key.pub

-rw-r--r--  1 root  wheel  347 Nov 28 06:43 ssh_host_key.pub

-rw-r--r--  1 root  wheel  238 Nov 28 06:43 ssh_host_rsa_key.pub



If any file has a mode more permissive than ""0644"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Note: SSH public key files may be found in other directories on the system depending on the installation.



Change the mode of public host key files under ""/etc/ssh"" to ""0644"" with the following command:



# chmod 0644 /etc/ssh/*.key.pub
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
