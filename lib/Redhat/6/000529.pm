# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000529
#
# VULN ID
#   V-58901
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000373
#
# RULE ID
#   SV-73331r1_rule
#
# STIG ID
#   RHEL-06-000529
#
# RULE TITLE
#   The sudo command must require authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000529;

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
    return 'V-58901';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000373';
}

sub get_rule_id {
    return 'SV-73331r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000529';
}

sub get_rule_title {
    return 'The sudo command must require authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""sudo"" command allows authorized users to run programs (including shells) as other users, system users, and root. The ""/etc/sudoers"" file is used to configure authorized ""sudo"" users as well as the programs they are allowed to run. Some configuration options in the ""/etc/sudoers"" file allow configured users to run programs without re-authenticating. Use of these configuration options makes it easier for one compromised account to be used to compromise other accounts.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify neither the ""NOPASSWD"" option nor the ""!authenticate"" option is configured for use in ""/etc/sudoers"" and associated files. Note that the ""#include"" and ""#includedir"" directives may be used to include configuration data from locations other than the defaults enumerated here.



# egrep '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d/*

# egrep '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d/*



If the ""NOPASSWD"" or ""!authenticate"" options are configured for use in ""/etc/sudoers"" or associated files, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Update the ""/etc/sudoers"" or other sudo configuration files to remove or comment out lines utilizing the ""NOPASSWD"" and ""!authenticate"" options.



# visudo

# visudo -f [other sudo configuration file]
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
