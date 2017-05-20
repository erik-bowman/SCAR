# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010340
#
# VULN ID
#   V-71947
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373-GPOS-00156
#
# RULE ID
#   SV-86571r1_rule
#
# STIG ID
#   RHEL-07-010340
#
# RULE TITLE
#   Users must provide a password for privilege escalation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010340;

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
    return 'V-71947';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000373-GPOS-00156';
}

sub get_rule_id {
    return 'SV-86571r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010340';
}

sub get_rule_title {
    return 'Users must provide a password for privilege escalation.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without re-authentication, users may access resources or perform tasks for which they do not have authorization.



When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.



Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system requires users to supply a password for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*



If any uncommented line is found with a ""NOPASSWD"" tag, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to require users to supply a password for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i nopasswd /etc/sudoers /etc/sudoers.d/*



Remove any occurrences of ""NOPASSWD"" tags in the file.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002038

The organization requires users to reauthenticate when organization-defined circumstances or situations requiring reauthentication.

NIST SP 800-53 Revision 4 :: IA-11




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
