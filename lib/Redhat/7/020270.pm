# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020270
#
# VULN ID
#   V-72001
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86625r1_rule
#
# STIG ID
#   RHEL-07-020270
#
# RULE TITLE
#   The system must not have unnecessary accounts.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020270;

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
    return 'V-72001';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86625r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020270';
}

sub get_rule_title {
    return 'The system must not have unnecessary accounts.';
}

sub get_discussion {
    return <<'DISCUSSION';
Accounts providing no operational purpose provide additional opportunities for system compromise. Unnecessary accounts include user accounts for individuals not requiring access to the system and application accounts for applications not installed on the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify all accounts on the system are assigned to an active system, application, or user account.



Obtain the list of authorized system accounts from the Information System Security Officer (ISSO).



Check the system accounts on the system with the following command:



# more /etc/passwd

root:x:0:0:root:/root:/bin/bash

bin:x:1:1:bin:/bin:/sbin/nologin

daemon:x:2:2:daemon:/sbin:/sbin/nologin

sync:x:5:0:sync:/sbin:/bin/sync

shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown

halt:x:7:0:halt:/sbin:/sbin/halt

games:x:12:100:games:/usr/games:/sbin/nologin

gopher:x:13:30:gopher:/var/gopher:/sbin/nologin



Accounts such as ""games"" and ""gopher"" are not authorized accounts as they do not support authorized system functions.



If the accounts on the system do not match the provided documentation, or accounts that do not support an authorized system function are present, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the system so all accounts on the system are assigned to an active system, application, or user account.



Remove accounts that do not support approved system activities or that allow for a normal user to perform administrative-level actions.



Document all authorized accounts on the system.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000366

The organization implements the security configuration settings.

NIST SP 800-53 :: CM-6 b

NIST SP 800-53A :: CM-6.1 (iv)

NIST SP 800-53 Revision 4 :: CM-6 b




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
