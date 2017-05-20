# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000515
#
# VULN ID
#   V-38460
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-000104
#
# RULE ID
#   SV-50260r1_rule
#
# STIG ID
#   RHEL-06-000515
#
# RULE TITLE
#   The NFS server must not have the all_squash option enabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000515;

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
    return 'V-38460';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-000104';
}

sub get_rule_id {
    return 'SV-50260r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000515';
}

sub get_rule_title {
    return 'The NFS server must not have the all_squash option enabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
The ""all_squash"" option maps all client requests to a single anonymous uid/gid on the NFS server, negating the ability to track file access by user ID.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the NFS server is read-only, in support of unrestricted access to organizational content, this is not applicable.



The related ""root_squash"" option provides protection against remote administrator-level access to NFS server content.  Its use is not a finding.



To verify the ""all_squash"" option has been disabled, run the following command:



# grep all_squash /etc/exports





If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Remove any instances of the ""all_squash"" option from the file ""/etc/exports"".  Restart the NFS daemon for the changes to take effect.



# service nfs restart
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000764

The information system uniquely identifies and authenticates organizational users (or processes acting on behalf of organizational users).

NIST SP 800-53 :: IA-2

NIST SP 800-53A :: IA-2.1

NIST SP 800-53 Revision 4 :: IA-2




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
