# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000004
#
# VULN ID
#   V-38467
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000044
#
# RULE ID
#   SV-50267r1_rule
#
# STIG ID
#   RHEL-06-000004
#
# RULE TITLE
#   The system must use a separate file system for the system audit data path.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000004;

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
    if ( defined $self->{parent}->{fstab}->{'/var/log/audit'} ) {
        $self->_set_finding_status('NF');
    }
    else {
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
    return 'V-38467';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000044';
}

sub get_rule_id {
    return 'SV-50267r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000004';
}

sub get_rule_title {
    return
        'The system must use a separate file system for the system audit data path.';
}

sub get_discussion {
    return <<'DISCUSSION';
Placing ""/var/log/audit"" in its own partition enables better separation between audit files and other files, and helps ensure that auditing cannot be halted due to the partition running out of space.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Run the following command to determine if ""/var/log/audit"" is on its own partition or logical volume:



$ mount | grep ""on /var/log/audit ""



If ""/var/log/audit"" has its own partition or volume group, a line will be returned.

If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Audit logs are stored in the ""/var/log/audit"" directory. Ensure that it has its own partition or logical volume at installation time, or migrate it later using LVM. Make absolutely certain that it is large enough to store all audit logs that will be created by the auditing daemon.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000137

The organization allocates audit record storage capacity.

NIST SP 800-53 :: AU-4

NIST SP 800-53A :: AU-4.1 (i)




CCI
}

1;

__END__
