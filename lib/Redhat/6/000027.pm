# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000027
#
# VULN ID
#   V-38492
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000109
#
# RULE ID
#   SV-50293r1_rule
#
# STIG ID
#   RHEL-06-000027
#
# RULE TITLE
#   The system must prevent the root account from logging in from virtual consoles.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000027;

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
    return 'V-38492';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000109';
}

sub get_rule_id {
    return 'SV-50293r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000027';
}

sub get_rule_title {
    return
        'The system must prevent the root account from logging in from virtual consoles.';
}

sub get_discussion {
    return <<'DISCUSSION';
Preventing direct root login to virtual console devices helps ensure accountability for actions taken on the system using the root account.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check for virtual console entries which permit root login, run the following command:



# grep '^vc/[0-9]' /etc/securetty



If any output is returned, then root logins over virtual console devices is permitted.

If root login over virtual console devices is permitted, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To restrict root logins through the (deprecated) virtual console devices, ensure lines of this form do not appear in ""/etc/securetty"":



vc/1

vc/2

vc/3

vc/4



Note:  Virtual console entries are not limited to those listed above.  Any lines starting with ""vc/"" followed by numerals should be removed.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000770

The organization requires individuals to be authenticated with an individual authenticator when a group authenticator is employed.

NIST SP 800-53 :: IA-2 (5) (b)

NIST SP 800-53A :: IA-2 (5).2 (ii)

NIST SP 800-53 Revision 4 :: IA-2 (5)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
