# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000335
#
# VULN ID
#   V-38694
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000118
#
# RULE ID
#   SV-50495r1_rule
#
# STIG ID
#   RHEL-06-000335
#
# RULE TITLE
#   The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000335;

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
    return 'V-38694';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000118';
}

sub get_rule_id {
    return 'SV-50495r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000335';
}

sub get_rule_title {
    return
        'The operating system must manage information system identifiers for users and devices by disabling the user identifier after an organization defined time period of inactivity.';
}

sub get_discussion {
    return <<'DISCUSSION';
Disabling inactive accounts ensures that accounts which may not have been responsibly removed are not available to attackers who may have compromised their credentials.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the ""INACTIVE"" setting, run the following command:



grep ""INACTIVE"" /etc/default/useradd



The output should indicate the ""INACTIVE"" configuration option is set to an appropriate integer as shown in the example below:



# grep ""INACTIVE"" /etc/default/useradd

INACTIVE=35



If it does not, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To specify the number of days after a password expires (which signifies inactivity) until an account is permanently disabled, add or correct the following lines in ""/etc/default/useradd"", substituting ""[NUM_DAYS]"" appropriately:



INACTIVE=[NUM_DAYS]



A value of 35 is recommended. If a password is currently on the verge of expiration, then 35 days remain until the account is automatically disabled. However, if the password will not expire for another 60 days, then 95 days could elapse until the account would be automatically disabled. See the ""useradd"" man page for more information. Determining the inactivity timeout must be done with careful consideration of the length of a ""normal"" period of inactivity for users in the particular environment. Setting the timeout too low incurs support costs and also has the potential to impact availability of the system to legitimate users.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000795

The organization manages information system identifiers by disabling the identifier after an organization defined time period of inactivity.

NIST SP 800-53 :: IA-4 e

NIST SP 800-53A :: IA-4.1 (iii)

NIST SP 800-53 Revision 4 :: IA-4 e




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
