# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000047
#
# VULN ID
#   V-38469
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000259
#
# RULE ID
#   SV-50269r3_rule
#
# STIG ID
#   RHEL-06-000047
#
# RULE TITLE
#   All system command files must have mode 755 or less permissive.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000047;

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
        if ( $self->{parent}->{bin_files}->{$bin_file}->{permissions}
            =~ /^\d\d(\d[67]|[67]\d)/msx )
        {
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
    return 'V-38469';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000259';
}

sub get_rule_id {
    return 'SV-50269r3_rule';
}

sub get_stig_id {
    return 'RHEL-06-000047';
}

sub get_rule_title {
    return 'All system command files must have mode 755 or less permissive.';
}

sub get_discussion {
    return <<'DISCUSSION';
System binaries are executed by privileged users, as well as system services, and restrictive permissions are necessary to ensure execution of these programs cannot be co-opted.
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



All files in these directories should not be group-writable or world-writable. To find system executables that are group-writable or world-writable, run the following command for each directory [DIR] which contains system executables:



$ find -L [DIR] -perm /022 -type f



If any system executables are found to be group-writable or world-writable, this is a finding.
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



If any file in these directories is found to be group-writable or world-writable, correct its permission with the following command:



# chmod go-w [FILE]
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
