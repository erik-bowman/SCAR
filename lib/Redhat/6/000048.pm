# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000048
#
# VULN ID
#   V-38472
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000259
#
# RULE ID
#   SV-50272r1_rule
#
# STIG ID
#   RHEL-06-000048
#
# RULE TITLE
#   All system command files must be owned by root.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000048;

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
    foreach my $bin_file ( keys %{ $self->{parent}->{bin_files} } ) {
        if ( $self->{parent}->{bin_files}->{$bin_file}->{owner} ne '0' ) {
            $self->_set_finding_status('O');
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
    return 'V-38472';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000259';
}

sub get_rule_id {
    return 'SV-50272r1_rule';
}

sub get_stig_id {
    return 'RHEL-06-000048';
}

sub get_rule_title {
    return 'All system command files must be owned by root.';
}

sub get_discussion {
    return <<'DISCUSSION';
System binaries are executed by privileged users as well as system services, and restrictive permissions are necessary to ensure that their execution of these programs cannot be co-opted.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
System executables are stored in the following directories by default:



/bin

/usr/bin

/usr/local/bin

/sbin

/usr/sbin

/usr/local/sbin



All files in these directories should not be group-writable or world-writable. To find system executables that are not owned by ""root"", run the following command for each directory [DIR] which contains system executables:



$ find -L [DIR] \! -user root





If any system executables are found to not be owned by root, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
System executables are stored in the following directories by default:



/bin

/usr/bin

/usr/local/bin

/sbin

/usr/sbin

/usr/local/sbin



If any file [FILE] in these directories is found to be owned by a user other than root, correct its ownership with the following command:



# chown root [FILE]
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-001499

The organization limits privileges to change software resident within software libraries.

NIST SP 800-53 :: CM-5 (6)

NIST SP 800-53A :: CM-5 (6).1

NIST SP 800-53 Revision 4 :: CM-5 (6)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
