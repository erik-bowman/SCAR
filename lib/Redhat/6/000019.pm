# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000019
#
# VULN ID
#   V-38491
#
# SEVERITY
#   high
#
# GROUP TITLE
#   SRG-OS-000248
#
# RULE ID
#   SV-50292r1_rule
#
# STIG ID
#   RHEL-06-000019
#
# RULE TITLE
#   There must be no .rhosts or hosts.equiv files on the system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000019;

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
    return 'V-38491';
}

sub get_severity {
    return 'high';
}

sub get_group_title {
    return 'SRG-OS-000248';
}

sub get_rule_id {
    return 'SV-50292r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000019';
}

sub get_rule_title {
    return 'There must be no .rhosts or hosts.equiv files on the system.';
}

sub get_discussion {
    return <<'DISCUSSION';
Trust files are convenient, but when used in conjunction with the R-services, they can allow unauthenticated access to a system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
The existence of the file ""/etc/hosts.equiv"" or a file named "".rhosts"" inside a user home directory indicates the presence of an Rsh trust relationship.

If these files exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The files ""/etc/hosts.equiv"" and ""~/.rhosts"" (in each user's home directory) list remote hosts and users that are trusted by the local system when using the rshd daemon. To remove these files, run the following command to delete them from any location.



# rm /etc/hosts.equiv







$ rm ~/.rhosts
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001436

The organization disables organization defined networking protocols within the information system deemed to be nonsecure except for explicitly identified components in support of specific operational requirements.

NIST SP 800-53 :: AC-17 (8)

NIST SP 800-53A :: AC-17 (8).1 (ii)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
