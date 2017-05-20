# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000519
#
# VULN ID
#   V-38447
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50247r3_rule
#
# STIG ID
#   RHEL-06-000519
#
# RULE TITLE
#   The system package management tool must verify contents of all files associated with packages.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000519;

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
    return 'V-38447';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50247r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000519';
}

sub get_rule_title {
    return
        'The system package management tool must verify contents of all files associated with packages.';
}

sub get_discussion {
    return <<'DISCUSSION';
The hash on important files like system executables should match the information given by the RPM database. Executables with erroneous hashes could be a sign of nefarious activity on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The following command will list which files on the system have file hashes different from what is expected by the RPM database.



# rpm -Va | awk '$1 ~ /..5/ && $2 != ""c""'





If any output is produced, verify that the changes were due to STIG application and have been documented with the ISSO.



If any output has not been documented with the ISSO, this is a finding.


CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The RPM package management system can check the hashes of installed software packages, including many that are important to system security. Run the following command to list which files on the system have hashes that differ from what is expected by the RPM database:



# rpm -Va | grep '^..5'



A ""c"" in the second column indicates that a file is a configuration file, which may appropriately be expected to change. If the file that has changed was not expected to then refresh from distribution media or online repositories.



rpm -Uvh [affected_package]



OR



yum reinstall [affected_package]
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

# ------------------------------------------------------------------------------

1;

__END__
