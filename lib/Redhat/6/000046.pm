# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000046
#
# VULN ID
#   V-38466
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000259
#
# RULE ID
#   SV-50266r4_rule
#
# STIG ID
#   RHEL-06-000046
#
# RULE TITLE
#   Library files must be owned by a system account.
#
# TODO: Create Check
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000046;

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
    return 'V-38466';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000259';
}

sub get_rule_id {
    return 'SV-50266r4_rule';
}

sub get_stig_id {
    return 'RHEL-06-000046';
}

sub get_rule_title {
    return 'Library files must be owned by a system account.';
}

sub get_discussion {
    return <<'DISCUSSION';
Files from shared library directories are loaded into the address space of processes (including privileged ones) or of the kernel itself at runtime. Proper ownership is necessary to protect the integrity of the system.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:



/lib

/lib64

/usr/lib

/usr/lib64

/usr/local/lib

/usr/local/lib64



Kernel modules, which can be added to the kernel during runtime, are stored in ""/lib/modules"". All files in these directories should not be group-writable or world-writable.  To find shared libraries that are not owned by ""root"" and do not match what is expected by the RPM, run the following command:



for i in /lib /lib64 /usr/lib /usr/lib64

do

  for j in `find -L $i \! -user root`

  do

    rpm -V -f $j | grep '^.....U'

  done

done





If the command returns any results, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
System-wide shared library files, which are linked to executables during process load time or run time, are stored in the following directories by default:



/lib

/lib64

/usr/lib

/usr/lib64

/usr/local/lib

/usr/local/lib64



If any file in these directories is found to be owned by a user other than ""root"" and does not match what is expected by the RPM, correct its ownership by running one of the following commands:





# rpm --setugids [PACKAGE_NAME]



Or



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
