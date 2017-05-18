#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000346
#
# VULN ID
#   V-38642
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50443r1_rule
#
# STIG ID
#   RHEL-06-000346
#
# RULE TITLE
#   The system default umask for daemons must be 027 or 022.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000346;

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
    $self->{VULN_ID} = 'V-38642';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-999999';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50443r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000346';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system default umask for daemons must be 027 or 022.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
The umask influences the permissions assigned to files created by a process at run time. An unnecessarily permissive umask could result in files being created with insecure permissions.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
To check the value of the ""umask"", run the following command:



$ grep umask /etc/init.d/functions



The output should show either ""022"" or ""027"".

If it does not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The file ""/etc/init.d/functions"" includes initialization parameters for most or all daemons started at boot time. The default umask of 022 prevents creation of group- or world-writable files. To set the default umask for daemons, edit the following line, inserting 022 or 027 for [UMASK] appropriately:



umask [UMASK]



Setting the umask to too restrictive a setting can cause serious errors at runtime. Many daemons on the system already individually restrict themselves to a umask of 077 in their own init scripts.
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
