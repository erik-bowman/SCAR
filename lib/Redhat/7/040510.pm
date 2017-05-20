# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040510
#
# VULN ID
#   V-72271
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000420-GPOS-00186
#
# RULE ID
#   SV-86895r1_rule
#
# STIG ID
#   RHEL-07-040510
#
# RULE TITLE
#   The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040510;

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
    return 'V-72271';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000420-GPOS-00186';
}

sub get_rule_id {
    return 'SV-86895r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-040510';
}

sub get_rule_title {
    return
        'The operating system must protect against or limit the effects of Denial of Service (DoS) attacks by validating the operating system is implementing rate-limiting measures on impacted network interfaces.';
}

sub get_discussion {
    return <<'DISCUSSION';
DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.



This requirement addresses the configuration of the operating system to mitigate the impact of DoS attacks that have occurred or are ongoing on system availability. For each system, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or establishing memory partitions). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system protects against or limits the effects of DoS attacks by ensuring the operating system is implementing rate-limiting measures on impacted network interfaces.



Check the firewall configuration with the following command:



Note: The command is to query rules for the public zone.



# firewall-cmd --direct --get-rule ipv4 filter IN_public_allow

rule ipv4 filter IN_public_allow 0 -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT



If a rule with both the limit and limit-burst arguments parameters does not exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Create a direct firewall rule to protect against DoS attacks with the following command:



Note: The command is to add a rule to the public zone.



# firewall-cmd --direct --add-rule ipv4 filter IN_public_allow 0 -p tcp -m limit --limit 25/minute --limit-burst 100  -j ACCEPT
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002385

The information system protects against or limits the effects of organization-defined types of denial of service attacks by employing organization-defined security safeguards.

NIST SP 800-53 Revision 4 :: SC-5




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
