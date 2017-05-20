# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000518
#
# VULN ID
#   V-38452
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50252r2_rule
#
# STIG ID
#   RHEL-06-000518
#
# RULE TITLE
#   The system package management tool must verify permissions on all files and directories associated with packages.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000518;

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
    return 'V-38452';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50252r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000518';
}

sub get_rule_title {
    return
        'The system package management tool must verify permissions on all files and directories associated with packages.';
}

sub get_discussion {
    return <<'DISCUSSION';
Permissions on system binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The following command will list which files and directories on the system have permissions different from what is expected by the RPM database:



# rpm -Va  | grep '^.M'



If there is any output, for each file or directory found, find the associated RPM package and compare the RPM-expected permissions with the actual permissions on the file or directory:



# rpm -qf [file or directory name]

# rpm -q --queryformat ""[%{FILENAMES} %{FILEMODES:perms}\n]"" [package] | grep  [filename]

# ls -dlL [filename]



If the existing permissions are more permissive than those expected by RPM, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The RPM package management system can restore file access permissions of package files and directories. The following command will update permissions on files and directories with permissions different from what is expected by the RPM database:



# rpm --setperms [package]
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
