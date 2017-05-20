# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040420
#
# VULN ID
#   V-72257
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86881r1_rule
#
# STIG ID
#   RHEL-07-040420
#
# RULE TITLE
#   The SSH private host key files must have mode 0600 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040420;

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
    return 'V-72257';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86881r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040420';
}

sub get_rule_title {
    return
        'The SSH private host key files must have mode 0600 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
If an unauthorized user obtains the private SSH host key file, the host could be impersonated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH private host key files have mode ""0600"" or less permissive.



The following command will find all SSH private key files on the system:



# find / -name '*ssh_host*key'



Check the mode of the private host key files under ""/etc/ssh"" file with the following command:



# ls -lL /etc/ssh/*key

-rw-------  1 root  wheel  668 Nov 28 06:43 ssh_host_dsa_key

-rw-------  1 root  wheel  582 Nov 28 06:43 ssh_host_key

-rw-------  1 root  wheel  887 Nov 28 06:43 ssh_host_rsa_key



If any file has a mode more permissive than ""0600"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the mode of SSH private host key files under ""/etc/ssh"" to ""0600"" with the following command:



# chmod 0600 /etc/ssh/ssh_host*key
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
