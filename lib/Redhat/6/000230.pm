# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000230
#
# VULN ID
#   V-38608
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000163
#
# RULE ID
#   SV-50409r1_rule
#
# STIG ID
#   RHEL-06-000230
#
# RULE TITLE
#   The SSH daemon must set a timeout interval on idle sessions.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000230;

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
    if ( !defined $self->{parent}->{'/etc/ssh/sshd_config'}
        ->{ClientAliveInterval}[1] )
    {
        if (defined $self->{parent}->{'/etc/ssh/sshd_config'}
            ->{ClientAliveInterval}[0] )
        {
            if (defined $self->{parent}->{'/etc/ssh/sshd_config'}
                ->{ClientAliveInterval}[0] eq '900' )
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
    return 'V-38608';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000163';
}

sub get_rule_id {
    return 'SV-50409r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000230';
}

sub get_rule_title {
    return 'The SSH daemon must set a timeout interval on idle sessions.';
}

sub get_discussion {
    return <<'DISCUSSION';
Causing idle users to be automatically logged out guards against compromises one system leading trivially to compromises on another.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to see what the timeout interval is:



# grep ClientAliveInterval /etc/ssh/sshd_config



If properly configured, the output should be:



ClientAliveInterval 900





If it is not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
SSH allows administrators to set an idle timeout interval. After this interval has passed, the idle user will be automatically logged out.



To set an idle timeout interval, edit the following line in ""/etc/ssh/sshd_config"" as follows:



ClientAliveInterval [interval]



The timeout [interval] is given in seconds. To have a timeout of 15 minutes, set [interval] to 900.



If a shorter timeout has already been set for the login shell, that value will preempt any SSH setting made here. Keep in mind that some processes may stop SSH from correctly detecting that the user is idle.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001133

The information system terminates the network connection associated with a communications session at the end of the session or after an organization-defined time period of inactivity.

NIST SP 800-53 :: SC-10

NIST SP 800-53A :: SC-10.1 (ii)

NIST SP 800-53 Revision 4 :: SC-10




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
