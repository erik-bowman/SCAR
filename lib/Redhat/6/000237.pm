# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000237
#
# VULN ID
#   V-38613
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000109
#
# RULE ID
#   SV-50414r1_rule
#
# STIG ID
#   RHEL-06-000237
#
# RULE TITLE
#   The system must not permit root logins using remote access programs such as ssh.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000237;

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
    my $self = bless \%{$parent}, $class;

    return $self;
}

sub check {
    my ($self) = @_;
    if ( defined $self->{sshd_config}->{PermitRootLogin} ) {
        if ( $self->{sshd_config}->{PermitRootLogin} eq 'no' ) {
            $self->_set_finding_status('NF');
        }
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('O');
    }
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
    return 'V-38613';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000109';
}

sub get_rule_id {
    return 'SV-50414r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000237';
}

sub get_rule_title {
    return
        'The system must not permit root logins using remote access programs such as ssh.';
}

sub get_discussion {
    return <<'DISCUSSION';
Permitting direct root login reduces auditable information about who ran privileged commands on the system and also allows direct attack attempts on root's password.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To determine how the SSH daemon's ""PermitRootLogin"" option is set, run the following command:



# grep -i PermitRootLogin /etc/ssh/sshd_config



If a line indicating ""no"" is returned, then the required value is set.

If the required value is not set, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The root user should never be allowed to log in to a system directly over a network. To disable root login via SSH, add or correct the following line in ""/etc/ssh/sshd_config"":



PermitRootLogin no
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
