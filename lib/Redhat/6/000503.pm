# ------------------------------------------------------------------------------
# NAME
#   Redhat::6::000503
#
# VULN ID
#   V-38490
#
# SEVERITY
#   medium
#
# GROUP TITLE
#   SRG-OS-000273
#
# RULE ID
#   SV-50291r5_rule
#
# STIG ID
#   RHEL-06-000503
#
# RULE TITLE
#   The operating system must enforce requirements for the connection of mobile devices to operating systems.
#
# TODO: Create Remediation
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

package Redhat::6::000503;

# Standard modules
use utf8;
use strict;
use warnings FATAL => 'all';

# Scar modules
use Scar qw{ run_modprobe };
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
    my @modprobe_results = run_modprobe('-n -v usb-storage');
    if ( !defined $modprobe_results[1] ) {
        if ( defined $modprobe_results[0] ) {
            if ( $modprobe_results[0] eq q{install /bin/true} ) {
                $self->_set_finding_status('NF');
            }
        }
    }
    if ( !defined $self->get_finding_status() ) {
        $self->_set_finding_status('O');
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
    return 'V-38490';
}

sub get_severity {
    return 'medium';
}

sub get_group_title {
    return 'SRG-OS-000273';
}

sub get_rule_id {
    return 'SV-50291r5_rule';
}

sub get_stig_id {
    return 'RHEL-06-000503';
}

sub get_rule_title {
    return
        'The operating system must enforce requirements for the connection of mobile devices to operating systems.';
}

sub get_discussion {
    return <<'DISCUSSION';
USB storage devices such as thumb drives can be used to introduce unauthorized software and other vulnerabilities. Support for these devices should be disabled and the devices themselves should be tightly controlled.
DISCUSSION
}

sub get_check_content {
    return <<'CHECK_CONTENT';
If the system is configured to prevent the loading of the ""usb-storage"" kernel module, it will contain lines inside any file in ""/etc/modprobe.d"" or the deprecated""/etc/modprobe.conf"". These lines instruct the module loading system to run another program (such as ""/bin/true"") upon a module ""install"" event. Run the following command to search for such lines in all files in ""/etc/modprobe.d"" and the deprecated ""/etc/modprobe.conf"":



$ grep -r usb-storage /etc/modprobe.conf /etc/modprobe.d | grep -i ""/bin/true""



If no line is returned, this is a finding.
CHECK_CONTENT
}

sub get_fix_content {
    return <<'FIX_CONTENT';
To prevent USB storage devices from being used, configure the kernel module loading system to prevent automatic loading of the USB storage driver. To configure the system to prevent the ""usb-storage"" kernel module from being loaded, add the following line to a file in the directory ""/etc/modprobe.d"":



install usb-storage /bin/true



This will prevent the ""modprobe"" program from loading the ""usb-storage"" module, but will not prevent an administrator (or another program) from using the ""insmod"" program to load the module manually.
FIX_CONTENT
}

sub get_cci {
    return <<'CCI';
CCI-000086

The organization enforces requirements for the connection of mobile devices to organizational information systems.

NIST SP 800-53 :: AC-19 d

NIST SP 800-53A :: AC-19.1 (iv)




CCI
}

# ------------------------------------------------------------------------------

1;

__END__
