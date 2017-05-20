# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000347
#
# VULN ID
#   V-38619
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000073
#
# RULE ID
#   SV-50420r2_rule
#
# STIG ID
#   RHEL-06-000347
#
# RULE TITLE
#   There must be no .netrc files on the system.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000347;

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
    return 'V-38619';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000073';
}

sub get_rule_id {
    return 'SV-50420r2_rule';
}

sub get_stig_id {
    return 'RHEL-06-000347';
}

sub get_rule_title {
    return 'There must be no .netrc files on the system.';
}

sub get_discussion {
    return <<'DISCUSSION';
Unencrypted passwords for remote FTP servers may be stored in "".netrc"" files. DoD policy requires passwords be encrypted in storage and not used in access scripts.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To check the system for the existence of any "".netrc"" files, run the following command:



$ sudo find /root /home -xdev -name .netrc



If any .netrc files exist, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
The "".netrc"" files contain logon information used to auto-logon into FTP servers and reside in the user's home directory. These files may contain unencrypted passwords to remote FTP servers making them susceptible to access by unauthorized users and should not be used. Any "".netrc"" files should be removed.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000196

The information system, for password-based authentication, stores only encrypted representations of passwords.

NIST SP 800-53 :: IA-5 (1) (c)

NIST SP 800-53A :: IA-5 (1).1 (v)

NIST SP 800-53 Revision 4 :: IA-5 (1) (c)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
