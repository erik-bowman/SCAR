# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000223
#
# VULN ID
#   V-38609
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50410r2_rule
#
# STIG ID
#   RHEL-06-000223
#
# RULE TITLE
#   The TFTP service must not be running.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000223;

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
    if ( !defined $self->{parent}->{service}->{'tftp-server'} ) {
        $self->_set_finding_status('NF');
    }
    else {
        if ( $self->{parent}->{service}->{'tftp-server'}->{status}
            =~ /^tftp-server\sis\sstopped/msx )
        {
            $self->_set_finding_status('NF');
        }
        else {
            $self->_set_finding_status('O');
        }
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
    return 'V-38609';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000248';
}

sub get_rule_id {
    return 'SV-50410r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000223';
}

sub get_rule_title {
    return 'The TFTP service must not be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling the ""tftp"" service ensures the system is not acting as a tftp server, which does not provide encryption or authentication.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check that the ""tftp"" service is disabled in system boot configuration, run the following command:



# chkconfig ""tftp"" --list



Output should indicate the ""tftp"" service has either not been installed, or has been disabled, as shown in the example below:



# chkconfig ""tftp"" --list

tftp off

OR

error reading information on service tftp: No such file or directory





If the service is running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""tftp"" service should be disabled. The ""tftp"" service can be disabled with the following command:



# chkconfig tftp off
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
}

1;

__END__