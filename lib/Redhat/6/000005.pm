# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000005
#
# VULN ID
#   V-38470
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000045
#
# RULE ID
#   SV-50270r2_rule
#
# STIG ID
#   RHEL-06-000005
#
# RULE TITLE
#   The audit system must alert designated staff members when the audit storage volume approaches capacity.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000005;

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
    if ( !defined $self->{parent}->{'/etc/audit/auditd.conf'}
        ->{space_left_action}[1] )
    {
        if (defined $self->{parent}->{'/etc/audit/auditd.conf'}
            ->{space_left_action}[0] )
        {
            if ( $self->{parent}->{'/etc/audit/auditd.conf'}
                ->{space_left_action}[0] =~ /^(?:syslog|email)$/imsx )
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
    return 'V-38470';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000045';
}

sub get_rule_id {
    return 'SV-50270r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000005';
}

sub get_rule_title {
    return
        'The audit system must alert designated staff members when the audit storage volume approaches capacity.';
}

sub get_discussion {
    return <<'DISCUSSION';
Notifying administrators of an impending disk space problem may allow them to take corrective action prior to any disruption.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to email the administrator when disk space is starting to run low:



# grep space_left_action /etc/audit/auditd.conf

space_left_action = email





If the system is not configured to send an email to the system administrator when disk space is starting to run low, this is a finding.  The ""syslog"" option is acceptable when it can be demonstrated that the local log management infrastructure notifies an appropriate administrator in a timely manner.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The ""auditd"" service can be configured to take an action when disk space starts to run low. Edit the file ""/etc/audit/auditd.conf"". Modify the following line, substituting [ACTION] appropriately:



space_left_action = [ACTION]



Possible values for [ACTION] are described in the ""auditd.conf"" man page. These include:



""ignore""

""syslog""

""email""

""exec""

""suspend""

""single""

""halt""





Set this to ""email"" (instead of the default, which is ""suspend"") as it is more likely to get prompt attention.  The ""syslog"" option is acceptable, provided the local log management infrastructure notifies an appropriate administrator in a timely manner.



RHEL-06-000521 ensures that the email generated through the operation ""space_left_action"" will be sent to an administrator.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000138

The organization configures auditing to reduce the likelihood of storage capacity being exceeded.

NIST SP 800-53 :: AU-4

NIST SP 800-53A :: AU-4.1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
