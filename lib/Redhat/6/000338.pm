# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000338
#
# VULN ID
#   V-38701
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50502r1_rule
#
# STIG ID
#   RHEL-06-000338
#
# RULE TITLE
#   The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000338;

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
    return 'V-38701';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50502r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000338';
}

sub get_rule_title {
    return
        'The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.';
}

sub get_discussion {
    return <<'DISCUSSION';
Using the ""-s"" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify ""tftp"" is configured by with the ""-s"" option by running the following command:



grep ""server_args"" /etc/xinetd.d/tftp



The output should indicate the ""server_args"" variable is configured with the ""-s"" flag, matching the example below:



# grep ""server_args"" /etc/xinetd.d/tftp

server_args = -s /var/lib/tftpboot



If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If running the ""tftp"" service is necessary, it should be configured to change its root directory at startup. To do so, ensure ""/etc/xinetd.d/tftp"" includes ""-s"" as a command line argument, as shown in the following example (which is also the default):



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
