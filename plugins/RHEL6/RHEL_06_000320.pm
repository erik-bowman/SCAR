#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   RHEL_06_000320
#
# VULN ID
#   V-38686
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000147
#
# RULE ID
#   SV-50487r1_rule
#
# STIG ID
#   RHEL-06-000320
#
# RULE TITLE
#   The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package RHEL_06_000320;

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
    $self->{VULN_ID} = 'V-38686';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000147';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50487r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000320';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
In ""iptables"" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to ""DROP"" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Run the following command to ensure the default ""FORWARD"" policy is ""DROP"":



grep "":FORWARD"" /etc/sysconfig/iptables



The output must be the following:



# grep "":FORWARD"" /etc/sysconfig/iptables

:FORWARD DROP [0:0]



If it is not, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in ""/etc/sysconfig/iptables"":



:FORWARD DROP [0:0]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001109

The information system at managed interfaces denies network communications traffic by default and allows network communications traffic by exception (i.e., deny all, permit by exception).

NIST SP 800-53 :: SC-7 (5)

NIST SP 800-53A :: SC-7 (5).1 (i) (ii)

NIST SP 800-53 Revision 4 :: SC-7 (5)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
