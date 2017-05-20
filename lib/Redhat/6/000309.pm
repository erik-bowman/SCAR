# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000309
#
# VULN ID
#   V-38677
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000104
#
# RULE ID
#   SV-50478r1_rule
#
# STIG ID
#   RHEL-06-000309
#
# RULE TITLE
#   The NFS server must not have the insecure file locking option enabled.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000309;

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
    return 'V-38677';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000104';
}

sub get_rule_id {
    return 'SV-50478r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000309';
}

sub get_rule_title {
    return
        'The NFS server must not have the insecure file locking option enabled.';
}

sub get_discussion {
    return <<'DISCUSSION';
Allowing insecure file locking could allow for sensitive data to be viewed or edited by an unauthorized user.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify insecure file locking has been disabled, run the following command:



# grep insecure_locks /etc/exports





If there is output, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
By default the NFS server requires secure file-lock requests, which require credentials from the client in order to lock a file. Most NFS clients send credentials with file lock requests, however, there are a few clients that do not send credentials when requesting a file-lock, allowing the client to only be able to lock world-readable files. To get around this, the ""insecure_locks"" option can be used so these clients can access the desired export. This poses a security risk by potentially allowing the client access to data for which it does not have authorization. Remove any instances of the ""insecure_locks"" option from the file ""/etc/exports"".
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