# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000281
#
# VULN ID
#   V-38637
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000278
#
# RULE ID
#   SV-50438r2_rule
#
# STIG ID
#   RHEL-06-000281
#
# RULE TITLE
#   The system package management tool must verify contents of all files associated with the audit package.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000281;

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
    return 'V-38637';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000278';
}

sub get_rule_id {
    return 'SV-50438r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000281';
}

sub get_rule_title {
    return
        'The system package management tool must verify contents of all files associated with the audit package.';
}

sub get_discussion {
    return <<'DISCUSSION';
The hash on important files like audit system executables should match the information given by the RPM database. Audit executables  with erroneous hashes could be a sign of nefarious activity on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The following command will list which audit files on the system have file hashes different from what is expected by the RPM database.



# rpm -V audit | awk '$1 ~ /..5/ && $2 != ""c""'





If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The RPM package management system can check the hashes of audit system package files. Run the following command to list which audit files on the system have hashes that differ from what is expected by the RPM database:



# rpm -V audit | grep '^..5'



A ""c"" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories.



rpm -Uvh [affected_package]



OR



yum reinstall [affected_package]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001496

The information system implements cryptographic mechanisms to protect the integrity of audit tools.

NIST SP 800-53 :: AU-9 (3)

NIST SP 800-53A :: AU-9 (3).1

NIST SP 800-53 Revision 4 :: AU-9 (3)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
