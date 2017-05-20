# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::010500
#
# VULN ID
#   V-71965
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000104-GPOS-00051
#
# RULE ID
#   SV-86589r1_rule
#
# STIG ID
#   RHEL-07-010500
#
# RULE TITLE
#   The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::010500;

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
    return 'V-71965';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000104-GPOS-00051';
}

sub get_rule_id {
    return 'SV-86589r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-010500';
}

sub get_rule_title {
    return
        'The operating system must uniquely identify and must authenticate organizational users (or processes acting on behalf of organizational users) using multifactor authentication.';
}

sub get_discussion {
    return <<'DISCUSSION';
To assure accountability and prevent unauthenticated access, organizational users must be identified and authenticated to prevent potential misuse and compromise of the system.



Organizational users include organizational employees or individuals the organization deems to have equivalent status of employees (e.g., contractors). Organizational users (and processes acting on behalf of users) must be uniquely identified and authenticated to all accesses, except for the following:



1) Accesses explicitly identified and documented by the organization. Organizations document specific user actions that can be performed on the information system without identification or authentication;



and



2) Accesses that occur through authorized use of group authenticators without individual authentication. Organizations may require unique identification of individuals in group accounts (e.g., shared privilege accounts) or for detailed accountability of individual activity.



Satisfies: SRG-OS-000104-GPOS-00051, SRG-OS-000106-GPOS-00053, SRG-OS-000107-GPOS-00054, SRG-OS-000109-GPOS-00056, SRG-OS-000108-GPOS-00055, SRG-OS-000108-GPOS-00057, SRG-OS-000108-GPOS-00058
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system requires multifactor authentication to uniquely identify organizational users using multifactor authentication.



Check to see if smartcard authentication is enforced on the system:



# authconfig --test | grep -i smartcard



The entry for use only smartcard for logon may be enabled, and the smartcard module and smartcard removal actions must not be blank.



If smartcard authentication is disabled or the smartcard and smartcard removal actions are blank, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to require individuals to be authenticated with a multifactor authenticator.



Enable smartcard logons with the following commands:



# authconfig --enablesmartcard --smartcardaction=1 --update

# authconfig --enablerequiresmartcard -update



Modify the ""/etc/pam_pkcs11/pkcs11_eventmgr.conf"" file to uncomment the following line:



#/usr/X11R6/bin/xscreensaver-command -lock



Modify the ""/etc/pam_pkcs11/pam_pkcs11.conf"" file to use the cackey module if required.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000766

The information system implements multifactor authentication for network access to non-privileged accounts.

NIST SP 800-53 :: IA-2 (2)

NIST SP 800-53A :: IA-2 (2).1

NIST SP 800-53 Revision 4 :: IA-2 (2)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
