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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-71849';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'high';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000257-GPOS-00098';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86473r2_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-010010';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The file permissions, ownership, and group membership of system files and commands must match the vendor values.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Discretionary access control is weakened if a user or group has access permissions to system files and directories greater than the default.



Satisfies: SRG-OS-000257-GPOS-00098, SRG-OS-000278-GPOS-00108
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
Verify the file permissions, ownership, and group membership of system files and commands match the vendor values.



Check the file permissions, ownership, and group membership of system files and commands with the following command:



# rpm -Va | grep '^.M'



If there is any output from the command indicating that the ownership or group of a system file or command, or a system file, has permissions less restrictive than the default, this is a finding.
CHECK_CONTENT
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
Run the following command to determine which package owns the file:



# rpm -qf <filename>



Reset the permissions of files within a package with the following command:



#rpm --setperms <packagename>



Reset the user and group ownership of files within a package with the following command:



#rpm --setugids <packagename>
FIX_CONTENT
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
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
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
