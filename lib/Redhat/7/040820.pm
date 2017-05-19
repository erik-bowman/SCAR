# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040820
#
# VULN ID
#   V-72317
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86941r1_rule
#
# STIG ID
#   RHEL-07-040820
#
# RULE TITLE
#   The system must not have unauthorized IP tunnels configured.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040820;

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
    $self->{VULN_ID} = 'V-72317';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86941r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040820';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system must not have unauthorized IP tunnels configured.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
IP tunneling mechanisms can be used to bypass network filtering. If tunneling is required, it must be documented with the Information System Security Officer (ISSO).
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the system does not have unauthorized IP tunnels configured.



Check to see if ""libreswan"" is installed with the following command:



# yum list installed libreswan

openswan-2.6.32-27.el6.x86_64



If ""libreswan"" is installed, check to see if the ""IPsec"" service is active with the following command:



# systemctl status ipsec

ipsec.service - Internet Key Exchange (IKE) Protocol Daemon for IPsec

   Loaded: loaded (/usr/lib/systemd/system/ipsec.service; disabled)

   Active: inactive (dead)



If the ""IPsec"" service is active, check to see if any tunnels are configured in ""/etc/ipsec.conf"" and ""/etc/ipsec.d/"" with the following commands:



# grep -i conn /etc/ipsec.conf

conn mytunnel



# grep -i conn /etc/ipsec.d/*.conf

conn mytunnel



If there are indications that a ""conn"" parameter is configured for a tunnel, ask the System Administrator if the tunnel is documented with the ISSO. If ""libreswan"" is installed, ""IPsec"" is active, and an undocumented tunnel is active, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Remove all unapproved tunnels from the system, or document them with the ISSO.
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
