# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000227
#
# VULN ID
#   V-38607
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000112
#
# RULE ID
#   SV-50408r1_rule
#
# STIG ID
#   RHEL-06-000227
#
# RULE TITLE
#   The SSH daemon must be configured to use only the SSHv2 protocol.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000227;

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
    if ( !defined $self->{parent}->{files}->{'/etc/ssh/sshd_config'}
        ->{Protocol}[1] )
    {
        if (defined $self->{parent}->{files}->{'/etc/ssh/sshd_config'}
            ->{Protocol}[0] )
        {
            if ( $self->{parent}->{files}->{'/etc/ssh/sshd_config'}
                ->{Protocol}[0] eq '2' )
            {
                $self->_set_finding_status('NF');
            }
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
    return 'V-38607';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000112';
}

sub get_rule_id {
    return 'SV-50408r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000227';
}

sub get_rule_title {
    return
        'The SSH daemon must be configured to use only the SSHv2 protocol.';
}

sub get_discussion {
    return <<'DISCUSSION';
SSH protocol version 1 suffers from design flaws that result in security vulnerabilities and should not be used.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check which SSH protocol version is allowed, run the following command:



# grep Protocol /etc/ssh/sshd_config



If configured properly, output should be



Protocol 2





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Only SSH protocol version 2 connections should be permitted. The default setting in ""/etc/ssh/sshd_config"" is correct, and can be verified by ensuring that the following line appears:



Protocol 2
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000774

The information system uses organization defined replay-resistant authentication mechanisms for network access to privileged accounts.

NIST SP 800-53 :: IA-2 (8)

NIST SP 800-53A :: IA-2 (8).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
