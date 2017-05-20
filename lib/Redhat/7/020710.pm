# ------------------------------------------------------------------------------
# NAME
#   Redhat::7::020710
#
# VULN ID
#   V-72033
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000480-GPOS-00227
#
# RULE ID
#   SV-86657r1_rule
#
# STIG ID
#   RHEL-07-020710
#
# RULE TITLE
#   All local initialization files must have mode 0740 or less permissive.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::7::020710;

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
    return 'V-72033';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000480-GPOS-00227';
}

sub get_rule_id {
    return 'SV-86657r1_rule';
}

sub get_stig_id {
    return 'RHEL-07-020710';
}

sub get_rule_title {
    return
        'All local initialization files must have mode 0740 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
Local initialization files are used to configure the user's shell environment upon logon. Malicious modification of these files could compromise accounts upon logon.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
Verify that all local initialization files have a mode of ""0740"" or less permissive.



Check the mode on all local initialization files with the following command:



Note: The example will be for the smithj user, who has a home directory of ""/home/smithj"".



# ls -al /home/smithj/.* | more

-rwxr-xr-x  1 smithj users        896 Mar 10  2011 .profile

-rwxr-xr-x  1 smithj users        497 Jan  6  2007 .login

-rwxr-xr-x  1 smithj users        886 Jan  6  2007 .something



If any local initialization files have a mode more permissive than ""0740"", this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
Set the mode of the local initialization files to ""0740"" with the following command:



Note: The example will be for the smithj user, who has a home directory of ""/home/smithj"".



# chmod 0740 /home/smithj/.<INIT_FILE>
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
