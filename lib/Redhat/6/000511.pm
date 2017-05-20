# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000511
#
# VULN ID
#   V-38464
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000047
#
# RULE ID
#   SV-50264r1_rule
#
# STIG ID
#   RHEL-06-000511
#
# RULE TITLE
#   The audit system must take appropriate action when there are disk errors on the audit storage volume.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000511;

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
        ->{disk_error_action}[1] )
    {
        if (defined $self->{parent}->{'/etc/audit/auditd.conf'}
            ->{disk_error_action}[0] )
        {
            if ( $self->{parent}->{'/etc/audit/auditd.conf'}
                ->{disk_error_action}[0]
                =~ /^(?:syslog|exec|single|halt)$/imsx )
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
    return 'V-38464';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000047';
}

sub get_rule_id {
    return 'SV-50264r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000511';
}

sub get_rule_title {
    return
        'The audit system must take appropriate action when there are disk errors on the audit storage volume.';
}

sub get_discussion {
    return <<'DISCUSSION';
Taking appropriate action in case of disk errors will minimize the possibility of losing audit records.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Inspect ""/etc/audit/auditd.conf"" and locate the following line to determine if the system is configured to take appropriate action when disk errors occur:



# grep disk_error_action /etc/audit/auditd.conf

disk_error_action = [ACTION]





If the system is configured to ""suspend"" when disk errors occur or ""ignore"" them, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Edit the file ""/etc/audit/auditd.conf"". Modify the following line, substituting [ACTION] appropriately:



disk_error_action = [ACTION]



Possible values for [ACTION] are described in the ""auditd.conf"" man page. These include:



""ignore""

""syslog""

""exec""

""suspend""

""single""

""halt""





Set this to ""syslog"", ""exec"", ""single"", or ""halt"".
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000140

The information system takes organization-defined actions upon audit failure (e.g., shut down information system, overwrite oldest audit records, stop generating audit records).

NIST SP 800-53 :: AU-5 b

NIST SP 800-53A :: AU-5.1 (iv)

NIST SP 800-53 Revision 4 :: AU-5 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
