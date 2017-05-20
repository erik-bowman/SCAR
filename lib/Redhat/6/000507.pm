# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000507
#
# VULN ID
#   V-38484
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000025
#
# RULE ID
#   SV-50285r2_rule
#
# STIG ID
#   RHEL-06-000507
#
# RULE TITLE
#   The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000507;

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
    return 'V-38484';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000025';
}

sub get_rule_id {
    return 'SV-50285r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000507';
}

sub get_rule_title {
    return
        'The operating system, upon successful logon, must display to the user the date and time of the last logon or access via ssh.';
}

sub get_discussion {
    return <<'DISCUSSION';
Users need to be aware of activity that occurs regarding their account. Providing users with information regarding the date and time of their last successful login allows the user to determine if any unauthorized activity has occurred and gives them an opportunity to notify administrators.



At ssh login, a user must be presented with the last successful login date and time.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the value associated with the ""PrintLastLog"" keyword in /etc/ssh/sshd_config:



# grep -i ""^PrintLastLog"" /etc/ssh/sshd_config



If the ""PrintLastLog"" keyword is not present, this is not a finding.  If the value is not set to ""yes"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Update the ""PrintLastLog"" keyword to ""yes"" in /etc/ssh/sshd_config:



PrintLastLog yes



While it is acceptable to remove the keyword entirely since the default action for the SSH daemon is to print the last logon date and time, it is preferred to have the value explicitly documented.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000052

The information system notifies the user, upon successful logon (access) to the system, of the date and time of the last logon (access).

NIST SP 800-53 :: AC-9

NIST SP 800-53A :: AC-9.1

NIST SP 800-53 Revision 4 :: AC-9




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
