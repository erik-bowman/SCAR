# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000526
#
# VULN ID
#   V-38437
#
# SEVERITY
#   low
#
# GROUP TITLE
#   SRG-OS-999999
#
# RULE ID
#   SV-50237r1_rule
#
# STIG ID
#   RHEL-06-000526
#
# RULE TITLE
#   Automated file system mounting tools must not be enabled unless needed.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000526;

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
    if ( defined $self->{parent}->{service}->{autofs} ) {
        for my $i ( 0 .. 6 ) {
            if ( $self->{parent}->{service}->{autofs}->{$i} ne 'off' ) {
                $self->_set_finding_status('O');
            }
        }
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('NF');
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
    return 'V-38437';
}

sub get_severity {
    return 'low';
}

sub get_group_title {
    return 'SRG-OS-999999';
}

sub get_rule_id {
    return 'SV-50237r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000526';
}

sub get_rule_title {
    return
        'Automated file system mounting tools must not be enabled unless needed.';
}

sub get_discussion {
    return <<'DISCUSSION';
All filesystems that are required for the successful operation of the system should be explicitly listed in ""/etc/fstab"" by an administrator. New filesystems should not be arbitrarily introduced via the automounter.



The ""autofs"" daemon mounts and unmounts filesystems, such as user home directories shared via NFS, on demand. In addition, autofs can be used to handle removable media, and the default configuration provides the cdrom device as ""/misc/cd"". However, this method of providing access to removable media is not common, so autofs can almost always be disabled if NFS is not in use. Even if NFS is required, it is almost always possible to configure filesystem mounts statically by editing ""/etc/fstab"" rather than relying on the automounter.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
To verify the ""autofs"" service is disabled, run the following command:



chkconfig --list autofs



If properly configured, the output should be the following:



autofs 0:off 1:off 2:off 3:off 4:off 5:off 6:off



Verify the ""autofs"" service is not running:



# service autofs status



If the autofs service is enabled or running, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
If the ""autofs"" service is not needed to dynamically mount NFS filesystems or removable media, disable the service for all runlevels:



# chkconfig --level 0123456 autofs off



Stop the service if it is already running:



# service autofs stop
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

1;

__END__
