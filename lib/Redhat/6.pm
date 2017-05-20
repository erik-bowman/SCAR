package Redhat::6;

# Standard modules
use utf8;
use strict;
use FindBin;
use Carp qw( croak );
use base qw( Redhat );
use warnings FATAL => 'all';

# Scar modules
use Scar qw( run_awk run_service run_chkconfig );
use Scar::Util::Log;

# Module version
our $VERSION = 0.01;

sub new {
    my ($class) = @_;
    my $self = bless {}, $class;

    my @chkconfig_entries = run_chkconfig('--list');
    $self->services(@chkconfig_entries);

    my @fstab_entries = run_awk(q<'/^[^#]/ { print $ 0}' /etc/fstab>);
    $self->filesystem_table(@fstab_entries);

    $self->_get_lib_permissions();
    $self->_get_bin_permissions();
    $self->_ingest_auditd_conf();
    $self->_ingest_auditsp_syslog_conf();
    $self->_ingest_sshd_config();
    $self->_check_rpm_integrity();

    return $self;
}

sub services {
    my ( $self, @chkconfig_entries ) = @_;

    foreach my $chkconfig_entry (@chkconfig_entries) {
        my @entry_properties = split /[:\s]+/msx, $chkconfig_entry;
        my $service_name = $self->service_properties(@entry_properties);
        $self->{service}->{$service_name}->{status}
            = run_service("$service_name status");
    }

    return $self;
}

sub service_properties {
    my ( $self, @entry_properties ) = @_;
    my $service_name = shift @entry_properties;

    while (@entry_properties) {
        my $runlevel_property = shift @entry_properties;
        my $runlevel_value    = shift @entry_properties;
        $self->{service}->{$service_name}->{$runlevel_property}
            = $runlevel_value;
    }

    return $service_name;
}

sub filesystem_table {
    my ( $self, @fstab_entries ) = @_;

    foreach my $fstab_entry (@fstab_entries) {

        my @entry_properties = split /\s+/msx, $fstab_entry;

        my ($device_property,  $directory_property, $type_property,
            $options_property, $dump_property,      $fsck_property
        ) = @entry_properties;

        $self->{fstab}->{$directory_property} = {
            device  => $device_property,
            type    => $type_property,
            options => $options_property,
            dump    => $dump_property,
            fsck    => $fsck_property,
        };
    }

    return $self;
}

1;

__END__
