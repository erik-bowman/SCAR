# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000343
#
# VULN ID
#   V-38649
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50450r1_rule
#
# STIG ID
#   RHEL-06-000343
#
# RULE TITLE
#   The system default umask for the csh shell must be 077.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000343;

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
    return 'V-38649';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50450r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000343';
}

sub get_rule_title {
    return 'The system default umask for the csh shell must be 077.';
}

sub get_discussion {
    return <<'DISCUSSION';
The umask value influences the permissions assigned to files when they are created. A misconfigured umask value could result in files with excessive permissions that can be read and/or written to by unauthorized users.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the ""umask"" setting is configured correctly in the ""/etc/csh.cshrc"" file by running the following command:



# grep ""umask"" /etc/csh.cshrc



All output must show the value of ""umask"" set to 077, as shown in the below:



# grep ""umask"" /etc/csh.cshrc

umask 077





If the above command returns no output, or if the umask is configured incorrectly, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To ensure the default umask for users of the C shell is set properly, add or correct the ""umask"" setting in ""/etc/csh.cshrc"" to read as follows:



umask 077
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