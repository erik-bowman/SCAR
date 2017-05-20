# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000231
#
# VULN ID
#   V-38610
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000126
#
# RULE ID
#   SV-50411r1_rule
#
# STIG ID
#   RHEL-06-000231
#
# RULE TITLE
#   The SSH daemon must set a timeout count on idle sessions.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000231;

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
        ->{ClientAliveCountMax}[1] )
    {
        if (defined $self->{parent}->{files}->{'/etc/ssh/sshd_config'}
            ->{ClientAliveCountMax}[0] )
        {
            if (defined $self->{parent}->{files}->{'/etc/ssh/sshd_config'}
                ->{ClientAliveCountMax}[0] eq '0' )
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
    return 'V-38610';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000126';
}

sub get_rule_id {
    return 'SV-50411r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000231';
}

sub get_rule_title {
    return 'The SSH daemon must set a timeout count on idle sessions.';
}

sub get_discussion {
    return <<'DISCUSSION';
This ensures a user login will be terminated as soon as the ""ClientAliveCountMax"" is reached.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To ensure the SSH idle timeout will occur when the ""ClientAliveCountMax"" is set, run the following command:



# grep ClientAliveCountMax /etc/ssh/sshd_config



If properly configured, output should be:



ClientAliveCountMax 0





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure the SSH idle timeout occurs precisely when the ""ClientAliveCountMax"" is set, edit ""/etc/ssh/sshd_config"" as follows:



ClientAliveCountMax 0
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000879

The organization terminates sessions and network connections when nonlocal maintenance is completed.

NIST SP 800-53 :: MA-4 e

NIST SP 800-53A :: MA-4.1 (vi)

NIST SP 800-53 Revision 4 :: MA-4 e




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
