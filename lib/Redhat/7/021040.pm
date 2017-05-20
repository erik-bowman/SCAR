# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::021040
#
# VULN ID
#   V-72049
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86673r1_rule
#
# STIG ID
#   RHEL-07-021040
#
# RULE TITLE
#   The umask must be set to 077 for all local interactive user accounts.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::021040;

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
    return 'V-72049';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86673r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-021040';
}

sub get_rule_title {
    return
        'The umask must be set to 077 for all local interactive user accounts.';
}

sub get_discussion {
    return <<'DISCUSSION';
The umask controls the default access mode assigned to newly created files. A umask of 077 limits new files to mode 700 or less permissive. Although umask can be represented as a four-digit number, the first digit representing special access modes is typically ignored or required to be ""0"". This requirement applies to the globally configured system defaults and the local interactive user defaults for each account on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that the default umask for all local interactive users is ""077"".



Identify the locations of all local interactive user home directories by looking at the ""/etc/passwd"" file.



Check all local interactive user initialization files for interactive users with the following command:



Note: The example is for a system that is configured to create users home directories in the ""/home"" directory.



# grep -i umask /home/*/.*



If any local interactive user initialization files are found to have a umask statement that has a value less restrictive than ""077"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Remove the umask statement from all local interactive users’ initialization files.



If the account is for an application, the requirement for a umask less restrictive than ""077"" can be documented with the Information System Security Officer, but the user agreement for access to the account must specify that the local interactive user must log on to their account first and then switch the user to the application account with the correct option to gain the account’s environment variables.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000318

The organization audits and reviews activities associated with configuration controlled changes to the system.

NIST SP 800-53 :: CM-3 e

NIST SP 800-53A :: CM-3.1 (v)

NIST SP 800-53 Revision 4 :: CM-3 f



CCI-000368

The organization documents any deviations from the established configuration settings for organization-defined information system components based on organization-defined operational requirements.

NIST SP 800-53 :: CM-6 c

NIST SP 800-53A :: CM-6.1 (v)

NIST SP 800-53 Revision 4 :: CM-6 c



CCI-001812

The information system prohibits user installation of software without explicit privileged status.

NIST SP 800-53 Revision 4 :: CM-11 (2)



CCI-001813

The information system enforces access restrictions.

NIST SP 800-53 Revision 4 :: CM-5 (1)



CCI-001814

The Information system supports auditing of the enforcement actions.

NIST SP 800-53 Revision 4 :: CM-5 (1)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
