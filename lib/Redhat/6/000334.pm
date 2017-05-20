# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000334
#
# VULN ID
#   V-38692
#
# SEVERITY
#   low
#
# GROUP TITLE
#   GEN006660
#
# RULE ID
#   SV-50493r1_rule
#
# STIG ID
#   RHEL-06-000334
#
# RULE TITLE
#   Accounts must be locked upon 35 days of inactivity.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000334;

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
    return 'V-38692';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'GEN006660';
}

sub get_rule_id {
    return 'SV-50493r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000334';
}

sub get_rule_title {
    return 'Accounts must be locked upon 35 days of inactivity.';
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
CCI-000017

The information system automatically disables inactive accounts after an organization-defined time period.

NIST SP 800-53 :: AC-2 (3)

NIST SP 800-53A :: AC-2 (3).1 (ii)

NIST SP 800-53 Revision 4 :: AC-2 (3)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
