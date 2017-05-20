# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010010
#
# VULN ID
#   V-71849
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000257-GPOS-00098
#
# RULE ID
#   SV-86473r2_rule
#
# STIG ID
#   RHEL-07-010010
#
# RULE TITLE
#   The file permissions, ownership, and group membership of system files and commands must match the vendor values.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010010;

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
    return 'V-71849';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000257-GPOS-00098';
}

sub get_rule_id {
    return 'SV-86473r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010010';
}

sub get_rule_title {
    return
        'The file permissions, ownership, and group membership of system files and commands must match the vendor values.';
}

sub get_discussion {
    return <<'DISCUSSION';
Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.



Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.



Check the file permissions, ownership, and group membership of system files and commands with the following command:



# rpm -Va | grep '^.M'



If there is any output from the command indicating that the ownership or group of a system file or command, or a system file, has permissions less restrictive than the default, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Run the following command to determine which package owns the file:



# rpm -qf <filename>



Reset the permissions of files within a package with the following command:



#rpm --setperms <packagename>



Reset the user and group ownership of files within a package with the following command:



#rpm --setugids <packagename>
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001494

The information system protects audit tools from unauthorized modification.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9



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
