# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000236
#
# VULN ID
#   V-38612
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000106
#
# RULE ID
#   SV-50413r1_rule
#
# STIG ID
#   RHEL-06-000236
#
# RULE TITLE
#   The SSH daemon must not allow host-based authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000236;

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
    return 'V-38612';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000106';
}

sub get_rule_id {
    return 'SV-50413r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000236';
}

sub get_rule_title {
    return 'The SSH daemon must not allow host-based authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
SSH trust relationships mean a compromise on one host can allow an attacker to move trivially to other hosts.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine how the SSH daemon's ""HostbasedAuthentication"" option is set, run the following command:



# grep -i HostbasedAuthentication /etc/ssh/sshd_config



If no line, a commented line, or a line indicating the value ""no"" is returned, then the required value is set.

If the required value is not set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
SSH's cryptographic host-based authentication is more secure than "".rhosts"" authentication, since hosts are cryptographically authenticated. However, it is not recommended that hosts unilaterally trust one another, even within an organization.



To disable host-based authentication, add or correct the following line in ""/etc/ssh/sshd_config"":



HostbasedAuthentication no
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000766

The information system implements multifactor authentication for network access to non-privileged accounts.

NIST SP 800-53 :: IA-2 (2)

NIST SP 800-53A :: IA-2 (2).1

NIST SP 800-53 Revision 4 :: IA-2 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
