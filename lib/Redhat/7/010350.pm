# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010350
#
# VULN ID
#   V-71949
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373-GPOS-00156
#
# RULE ID
#   SV-86573r2_rule
#
# STIG ID
#   RHEL-07-010350
#
# RULE TITLE
#   Users must re-authenticate for privilege escalation.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010350;

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
    return 'V-71949';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000373-GPOS-00156';
}

sub get_rule_id {
    return 'SV-86573r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-010350';
}

sub get_rule_title {
    return 'Users must re-authenticate for privilege escalation.';
}

sub get_discussion {
    return <<'DISCUSSION';
Without re-authentication, users may access resources or perform tasks for which they do not have authorization.



When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.



Satisfies: SRG-OS-000373-GPOS-00156, SRG-OS-000373-GPOS-00157, SRG-OS-000373-GPOS-00158
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system requires users to reauthenticate for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



# grep -i authenticate /etc/sudoers /etc/sudoers.d/*



If any line is found with a ""!authenticate"" tag, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to require users to reauthenticate for privilege escalation.



Check the configuration of the ""/etc/sudoers"" and ""/etc/sudoers.d/*"" files with the following command:



Remove any occurrences of ""!authenticate"" tags in the file.
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
