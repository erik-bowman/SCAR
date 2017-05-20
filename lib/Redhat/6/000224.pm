# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000224
#
# VULN ID
#   V-38605
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50406r2_rule
#
# STIG ID
#   RHEL-06-000224
#
# RULE TITLE
#   The cron service must be running.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000224;

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
    if ( defined $self->{parent}->{service}->{crond} ) {
        if ( $self->{parent}->{service}->{crond}->{status}
            =~ /^crond\s+[(]pid\s+\d+[)]\s+is\srunning[.]{3}$/msx )
        {
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
    return 'V-38605';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50406r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000224';
}

sub get_rule_title {
    return 'The cron service must be running.';
}

sub get_discussion {
    return <<'DISCUSSION';
Due to its usage for maintenance and security-supporting tasks, enabling the cron daemon is essential.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine the current status of the ""crond"" service:



# service crond status



If the service is enabled, it should return the following:



crond is running...





If the service is not running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""crond"" service is used to execute commands at preconfigured times. It is required by almost all systems to perform necessary maintenance tasks, such as notifying root of system activity. The ""crond"" service can be enabled with the following commands:



# chkconfig crond on

# service crond start
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

1;

__END__
