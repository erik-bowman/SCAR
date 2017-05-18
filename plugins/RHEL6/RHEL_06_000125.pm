#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000125
#
# VULN ID
#   V-38515
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000096
#
# RULE ID
#   SV-50316r4_rule
#
# STIG ID
#   RHEL-06-000125
#
# RULE TITLE
#   The Stream Control Transmission Protocol (SCTP) must be disabled unless required.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000125;

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
    $self->{VULN_ID} = 'V-38515';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000096';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50316r4_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000125';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The Stream Control Transmission Protocol (SCTP) must be disabled unless required.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Disabling SCTP protects the system against exploitation of any flaws in its implementation.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
If the system is configured to prevent the loading of the ""sctp"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r sctp /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The Stream Control Transmission Protocol (SCTP) is a transport layer protocol, designed to support the idea of message-oriented communication, with several streams of messages within one connection. To configure the system to prevent the ""sctp"" kernel module from being loaded, add the following line to a file in the directory ""/etc/modprobe.d"":



install sctp /bin/true
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000382

The organization configures the information system to prohibit or restrict the use of organization defined functions, ports, protocols, and/or services.

NIST SP 800-53 :: CM-7

NIST SP 800-53A :: CM-7.1 (iii)

NIST SP 800-53 Revision 4 :: CM-7 b




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
