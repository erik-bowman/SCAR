# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040520
#
# VULN ID
#   V-72273
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86897r1_rule
#
# STIG ID
#   RHEL-07-040520
#
# RULE TITLE
#   The operating system must enable an application firewall, if available.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040520;

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
    return 'V-72273';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86897r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040520';
}

sub get_rule_title {
    return
        'The operating system must enable an application firewall, if available.';
}

sub get_discussion {
    return <<'DISCUSSION';
Firewalls protect computers from network attacks by blocking or limiting access to open network ports. Application firewalls limit which applications are allowed to communicate over the network.



Satisfies: SRG-OS-000480-GPOS-00227, SRG-OS-000480-GPOS-00231, SRG-OS-000480-GPOS-00232
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system enabled an application firewall.



Check to see if ""firewalld"" is installed with the following command:



# yum list installed firewalld

firewalld-0.3.9-11.el7.noarch.rpm



If the ""firewalld"" package is not installed, ask the System Administrator if another firewall application (such as iptables) is installed.



If an application firewall is not installed, this is a finding.



Check to see if the firewall is loaded and active with the following command:



# systemctl status firewalld

firewalld.service - firewalld - dynamic firewall daemon



   Loaded: loaded (/usr/lib/systemd/system/firewalld.service; enabled)

   Active: active (running) since Tue 2014-06-17 11:14:49 CEST; 5 days ago



If ""firewalld"" does not show a status of ""loaded"" and ""active"", this is a finding.



Check the state of the firewall:



# firewall-cmd --state

running



If ""firewalld"" does not show a state of ""running"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Ensure the operating system's application firewall is enabled.



Install the ""firewalld"" package, if it is not on the system, with the following command:



# yum install firewalld



Start the firewall via ""systemctl"" with the following command:



# systemctl start firewalld
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
