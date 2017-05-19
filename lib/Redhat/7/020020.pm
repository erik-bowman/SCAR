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

sub VULN_ID {
    my ($self) = @_;
    $self->{VULN_ID} = 'V-71971';
    return $self->{VULN_ID};
}

sub SEVERITY {
    my ($self) = @_;
    $self->{SEVERITY} = 'medium';
    return $self->{SEVERITY};
}

sub GROUP_TITLE {
    my ($self) = @_;
    $self->{GROUP_TITLE} = 'SRG-OS-000324-GPOS-00125';
    return $self->{GROUP_TITLE};
}

sub RULE_ID {
    my ($self) = @_;
    $self->{RULE_ID} = 'SV-86595r1_rule';
    return $self->{RULE_ID};
}

sub STIG_ID {
    my ($self) = @_;
    $self->{STIG_ID} = 'RHEL-07-020020';
    return $self->{STIG_ID};
}

sub RULE_TITLE {
    my ($self) = @_;
    $self->{RULE_TITLE}
        = 'The operating system must prevent non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.';
    return $self->{RULE_TITLE};
}

sub DISCUSSION {
    my ($self) = @_;
    $self->{DISCUSSION} = <<'DISCUSSION';
Preventing non-privileged users from executing privileged functions mitigates the risk that unauthorized individuals or processes may gain unnecessary access to information or privileges.



Privileged functions include, for example, establishing accounts, performing system integrity checks, or administering cryptographic key management activities. Non-privileged users are individuals who do not possess appropriate authorizations. Circumventing intrusion detection and prevention mechanisms or malicious code protection mechanisms are examples of privileged functions that require protection from non-privileged users.
DISCUSSION
    return $self->{DISCUSSION};
}

sub CHECK_CONTENT {
    my ($self) = @_;
    $self->{CHECK_CONTENT} = <<'CHECK_CONTENT';
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
    return $self->{CHECK_CONTENT};
}

sub FIX_CONTENT {
    my ($self) = @_;
    $self->{FIX_CONTENT} = <<'FIX_CONTENT';
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
    return $self->{FIX_CONTENT};
}

sub CCI {
    my ($self) = @_;
    $self->{CCI} = <<'CCI';
CCI-002165

The information system enforces organization-defined discretionary access control policies over defined subjects and objects.

NIST SP 800-53 Revision 4 :: AC-3 (4)



CCI-002235

The information system prevents non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures.

NIST SP 800-53 Revision 4 :: AC-6 (10)




CCI
    return $self->{CCI};
}

# ------------------------------------------------------------------------------

1;

__END__
