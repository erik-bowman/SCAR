# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000120
#
# VULN ID
#   V-38513
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000231
#
# RULE ID
#   SV-50314r1_rule
#
# STIG ID
#   RHEL-06-000120
#
# RULE TITLE
#   The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000120;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38513';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000231';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50314r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000120';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.';
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
Inspect the file ""/etc/sysconfig/iptables"" to determine the default policy for the INPUT chain. It should be set to DROP.



# grep "":INPUT"" /etc/sysconfig/iptables



If the default policy for the INPUT chain is not set to DROP, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in ""/etc/sysconfig/iptables"":



:INPUT DROP [0:0]
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-000066

The organization enforces requirements for remote connections to the information system.

NIST SP 800-53 :: AC-17 e

NIST SP 800-53A :: AC-17.1 (v)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
