# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020020
#
# VULN ID
#   V-71971
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000324-GPOS-00125
#
# RULE ID
#   SV-86595r1_rule
#
# STIG ID
#   RHEL-07-020020
#
# RULE TITLE
#   The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020020;

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
    return 'V-71971';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000324-GPOS-00125';
}

sub get_rule_id {
    return 'SV-86595r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020020';
}

sub get_rule_title {
    return
        'The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.';
}

sub get_discussion {
    return <<'DISCUSSION';
Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.



Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the operating system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.



Get a list of authorized users (other than System Administrator and guest accounts) for the system.



Check the list against the system by using the following command:



# semanage login -l | more

Login Name  SELinux User   MLS/MCS Range  Service

__default__  user_u    s0-s0:c0.c1023   *

root   unconfined_u   s0-s0:c0.c1023   *

system_u  system_u   s0-s0:c0.c1023   *

joe  staff_u   s0-s0:c0.c1023   *



All administrators must be mapped to the ""sysadm_u"" or ""staff_u"" users with the appropriate domains (sysadm_t and staff_t).



All authorized non-administrative users must be mapped to the ""user_u"" role or the appropriate domain (user_t).



If they are not mapped in this way, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the operating system to prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.



Use the following command to map a new user to the ""sysdam_u"" role:



#semanage login -a -s sysadm_u <username>



Use the following command to map an existing user to the ""sysdam_u"" role:



#semanage login -m -s sysadm_u <username>



Use the following command to map a new user to the ""staff_u"" role:



#semanage login -a -s staff_u <username>



Use the following command to map an existing user to the ""staff_u"" role:



#semanage login -m -s staff_u <username>



Use the following command to map a new user to the ""user_u"" role:



# semanage login -a -s user_u <username>



Use the following command to map an existing user to the ""user_u"" role:



# semanage login -m -s user_u <username>
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)



CCI-002235

The information system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

NIST SP 800-53 Revision 4 :: AC-6 (10)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
