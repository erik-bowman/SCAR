# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000060
#
# VULN ID
#   V-38572
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000072
#
# RULE ID
#   SV-50373r2_rule
#
# STIG ID
#   RHEL-06-000060
#
# RULE TITLE
#   The system must require at least eight characters be changed between the old and new passwords during a password change.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000060;

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
    return 'V-38572';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000072';
}

sub get_rule_id {
    return 'SV-50373r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000060';
}

sub get_rule_title {
    return
        'The system must require at least eight characters be changed between the old and new passwords during a password change.';
}

sub get_discussion {
    return <<'DISCUSSION';
Requiring a minimum number of different characters during password changes ensures that newly changed passwords should not resemble previously compromised ones. Note that passwords which are changed on compromised systems will still be compromised, however.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check how many characters must differ during a password change, run the following command:



$ grep pam_cracklib /etc/pam.d/system-auth



The ""difok"" parameter will indicate how many characters must differ. The DoD requires eight characters differ during a password change. This would appear as ""difok=8"".



If difok is not found or not set to the required value, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The pam_cracklib module's ""difok"" parameter controls requirements for usage of different characters during a password change. Add ""difok=[NUM]"" after pam_cracklib.so to require differing characters when changing passwords, substituting [NUM] appropriately. The DoD requirement is 8.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000195

The information system, for password-based authentication, when new passwords are created, enforces that at least an organization-defined number of characters are changed.

NIST SP 800-53 :: IA-5 (1) (b)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (b)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
