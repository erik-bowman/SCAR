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
    return 'V-38513';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000231';
}

sub get_rule_id {
    return 'SV-50314r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000120';
}

sub get_rule_title {
    return
        'The systems local IPv4 firewall must implement a deny-all, allow-by-exception policy for inbound packets.';
}

sub get_discussion {
    return <<'DISCUSSION';
In ""iptables"" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to ""DROP"" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect the file ""/etc/sysconfig/iptables"" to determine the default policy for the INPUT chain. It should be set to DROP.



# grep "":INPUT"" /etc/sysconfig/iptables



If the default policy for the INPUT chain is not set to DROP, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the default policy to DROP (instead of ACCEPT) for the built-in INPUT chain which processes incoming packets, add or correct the following line in ""/etc/sysconfig/iptables"":



:INPUT DROP [0:0]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000066

The organization enforces requirements for remote connections to the information system.

NIST SP 800-53 :: AC-17 e

NIST SP 800-53A :: AC-17.1 (v)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
