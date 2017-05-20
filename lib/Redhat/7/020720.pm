# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020720
#
# VULN ID
#   V-72035
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86659r2_rule
#
# STIG ID
#   RHEL-07-020720
#
# RULE TITLE
#   All local interactive user initialization files executable search paths must contain only paths that resolve to the users home directory.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020720;

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
    return 'V-72035';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86659r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-020720';
}

sub get_rule_title {
    return
        'All local interactive user initialization files executable search paths must contain only paths that resolve to the users home directory.';
}

sub get_discussion {
    return <<'DISCUSSION';
The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user’s home directory), executables in these directories may be executed instead of system commands. This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the Information System Security Officer (ISSO).
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that all local interactive user initialization files' executable search path statements do not contain statements that will reference a working directory other than the users’ home directory.



Check the executable search path statement for all local interactive user initialization files in the users' home directory with the following commands:



Note: The example will be for the smithj user, which has a home directory of ""/home/smithj"".



# grep -i path /home/smithj/.*

/home/smithj/.bash_profile:PATH=$PATH:$HOME/.local/bin:$HOME/bin

/home/smithj/.bash_profile:export PATH



If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Configure the ""/etc/fstab"" to use the ""nosuid"" option on file systems that contain user home directories for interactive users.
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
