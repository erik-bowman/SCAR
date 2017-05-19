# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040600
#
# VULN ID
#   V-72281
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86905r1_rule
#
# STIG ID
#   RHEL-07-040600
#
# RULE TITLE
#   For systems using DNS resolution, at least two name servers must be configured.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040600;

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
    $self->{VULN_ID} = 'V-72281';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'low';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000480-GPOS-00227';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86905r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-040600';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'For systems using DNS resolution, at least two name servers must be configured.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
To provide availability for name resolution services, multiple redundant name servers are mandated. A failure in name resolution could lead to the failure of security functions requiring name resolution, which may include time synchronization, centralized authentication, and remote system logging.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Determine whether the system is using local or DNS name resolution with the following command:



# grep hosts /etc/nsswitch.conf

hosts:   files dns



If the DNS entry is missing from the host’s line in the ""/etc/nsswitch.conf"" file, the ""/etc/resolv.conf"" file must be empty.



Verify the ""/etc/resolv.conf"" file is empty with the following command:



# ls -al /etc/resolv.conf

-rw-r--r--  1 root root        0 Aug 19 08:31 resolv.conf



If local host authentication is being used and the ""/etc/resolv.conf"" file is not empty, this is a finding.



If the DNS entry is found on the host’s line of the ""/etc/nsswitch.conf"" file, verify the operating system is configured to use two or more name servers for DNS resolution.



Determine the name servers used by the system with the following command:



# grep nameserver /etc/resolv.conf

nameserver 192.168.1.2

nameserver 192.168.1.3



If less than two lines are returned that are not commented out, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Configure the operating system to use two or more name servers for DNS resolution.



Edit the ""/etc/resolv.conf"" file to uncomment or add the two or more ""nameserver"" option lines with the IP address of local authoritative name servers. If local host resolution is being performed, the ""/etc/resolv.conf"" file must be empty. An empty ""/etc/resolv.conf"" file can be created as follows:



# echo -n > /etc/resolv.conf



And then make the file immutable with the following command:



# chattr +i /etc/resolv.conf



If the ""/etc/resolv.conf"" file must be mutable, the required configuration must be documented with the Information System Security Officer (ISSO) and the file must be verified by the system file integrity tool.
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
