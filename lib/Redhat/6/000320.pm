# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000320
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

package Redhat::6::000320;

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
    return 'V-38686';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000147';
}

sub get_rule_id {
    return 'SV-50487r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000320';
}

sub get_rule_title {
    return
        'The systems local firewall must implement a deny-all, allow-by-exception policy for forwarded packets.';
}

sub get_discussion {
    return <<'DISCUSSION';
In ""iptables"" the default policy is applied only after all the applicable rules in the table are examined for a match. Setting the default policy to ""DROP"" implements proper design for a firewall, i.e., any packets which are not explicitly permitted should not be accepted.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to ensure the default ""FORWARD"" policy is ""DROP"":



grep "":FORWARD"" /etc/sysconfig/iptables



The output must be the following:



# grep "":FORWARD"" /etc/sysconfig/iptables

:FORWARD DROP [0:0]



If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To set the default policy to DROP (instead of ACCEPT) for the built-in FORWARD chain which processes packets that will be forwarded from one interface to another, add or correct the following line in ""/etc/sysconfig/iptables"":



:FORWARD DROP [0:0]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001109

The information system at managed interfaces denies network communications traffic by default and allows network communications traffic by exception (i.e., deny all, permit by exception).

NIST SP 800-53 :: SC-7 (5)

NIST SP 800-53A :: SC-7 (5).1 (i) (ii)

NIST SP 800-53 Revision 4 :: SC-7 (5)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
