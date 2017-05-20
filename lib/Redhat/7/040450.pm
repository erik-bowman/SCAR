# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::040450
#
# VULN ID
#   V-72263
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86887r2_rule
#
# STIG ID
#   RHEL-07-040450
#
# RULE TITLE
#   The SSH daemon must perform strict mode checking of home directory configuration files.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::040450;

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
    return 'V-72263';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86887r2_rule';
}

sub get_stig_id {
    return 'RHEL-07-040450';
}

sub get_rule_title {
    return
        'The SSH daemon must perform strict mode checking of home directory configuration files.';
}

sub get_discussion {
    return <<'DISCUSSION';
If other users have access to modify user-specific SSH configuration files, they may be able to log on to the system as another user.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify the SSH daemon performs strict mode checking of home directory configuration files.



The location of the ""sshd_config"" file may vary if a different daemon is in use.



Inspect the ""sshd_config"" file with the following command:



# grep -i strictmodes /etc/ssh/sshd_config



StrictModes yes



If ""StrictModes"" is set to ""no"", is missing, or the returned line is commented out, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Uncomment the ""StrictModes"" keyword in ""/etc/ssh/sshd_config"" (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor) and set the value to ""yes"":



StrictModes yes



The SSH service must be restarted for changes to take effect.
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
