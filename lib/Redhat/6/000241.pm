# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000241
#
# VULN ID
#   V-38616
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000242
#
# RULE ID
#   SV-50417r1_rule
#
# STIG ID
#   RHEL-06-000241
#
# RULE TITLE
#   The SSH daemon must not permit user environment settings.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000241;

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
    my $self = bless \%{$parent}, $class;

    return $self;
}

sub check {
    my ($self) = @_;
    if ( defined $self->{sshd_config}->{PermitUserEnvironment} ) {
        if ( $self->{sshd_config}->{PermitUserEnvironment} eq 'no' ) {
            $self->_set_finding_status('NF');
        }
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('O');
    }
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
    return 'V-38616';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000242';
}

sub get_rule_id {
    return 'SV-50417r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000241';
}

sub get_rule_title {
    return 'The SSH daemon must not permit user environment settings.';
}

sub get_discussion {
    return <<'DISCUSSION';
SSH environment options potentially allow users to bypass access restriction in some configurations.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure users are not able to present environment daemons, run the following command:



# grep PermitUserEnvironment /etc/ssh/sshd_config



If properly configured, output should be:



PermitUserEnvironment no





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure users are not able to present environment options to the SSH daemon, add or correct the following line in ""/etc/ssh/sshd_config"":



PermitUserEnvironment no
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001414

The information system enforces approved authorizations for controlling the flow of information between interconnected systems based on organization-defined information flow control policies.

NIST SP 800-53 :: AC-4

NIST SP 800-53A :: AC-4.1 (iii)

NIST SP 800-53 Revision 4 :: AC-4




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
