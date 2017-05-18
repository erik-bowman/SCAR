#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000338
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

package RHEL_06_000338;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# SCAR modules
use SCAR;
use SCAR::Log;
use SCAR::Backup;

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
    $self->{VULN_ID} = 'V-38701';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50502r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000338';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The TFTP daemon must operate in secure mode which provides access only to a single directory on the host file system.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Using the ""-s"" option causes the TFTP service to only serve files from the given directory. Serving files from an intentionally specified directory reduces the risk of sharing files which should remain private.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify ""tftp"" is configured by with the ""-s"" option by running the following command:



grep ""server_args"" /etc/xinetd.d/tftp



The output should indicate the ""server_args"" variable is configured with the ""-s"" flag, matching the example below:



# grep ""server_args"" /etc/xinetd.d/tftp

server_args = -s /var/lib/tftpboot



If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
If running the ""tftp"" service is necessary, it should be configured to change its root directory at startup. To do so, ensure ""/etc/xinetd.d/tftp"" includes ""-s"" as a command line argument, as shown in the following example (which is also the default):



server_args = -s /var/lib/tftpboot
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
