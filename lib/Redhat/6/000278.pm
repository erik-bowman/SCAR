# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000278
#
# VULN ID
#   V-38663
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000256
#
# RULE ID
#   SV-50464r1_rule
#
# STIG ID
#   RHEL-06-000278
#
# RULE TITLE
#   The system package management tool must verify permissions on all files and directories associated with the audit package.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000278;

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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-38663';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000256';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-50464r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-06-000278';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The system package management tool must verify permissions on all files and directories associated with the audit package.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Permissions on audit binaries and configuration files that are too generous could allow an unauthorized user to gain privileges that they should not have. The permissions set by the vendor should be maintained. Any deviations from this baseline should be investigated.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
The following command will list which audit files on the system have permissions different from what is expected by the RPM database:



# rpm -V audit | grep '^.M'



If there is any output, for each file or directory found, compare the RPM-expected permissions with the permissions on the file or directory:



# rpm -q --queryformat ""[%{FILENAMES} %{FILEMODES:perms}\n]"" audit | grep  [filename]

# ls -lL [filename]



If the existing permissions are more permissive than those expected by RPM, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
The RPM package management system can restore file access permissions of the audit package files and directories. The following command will update audit files with permissions different from what is expected by the RPM database:



# rpm --setperms audit
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-001493

The information system protects audit tools from unauthorized access.

NIST SP 800-53 :: AU-9

NIST SP 800-53A :: AU-9.1

NIST SP 800-53 Revision 4 :: AU-9




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
