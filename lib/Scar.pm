package Scar;

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use Fcntl;
use Carp qw{ croak };
use base qw{ Exporter };
use POSIX qw{ strftime };
use English qw{ -no_match_vars };
use File::Spec::Functions;

# Module version
our $VERSION = 0.01;

# Exportables
our @EXPORT_OK = qw{
    run_awk run_grep run_service
    run_chkconfig run_find run_rpm
    run_modprobe
    implode_path explode_path make_path_absolute
    get_strftime get_strfdate read_file
    get_current_directory
    get_file_owner get_file_group get_file_permissions
};

sub implode_path {
    my @path_components = @_;
    return File::Spec::Functions::catdir(@path_components);
}

sub explode_path {
    my @directories = @_;
    return File::Spec::Functions::splitpath(@directories);
}

sub make_path_absolute {
    my ( $file, $base ) = @_;
    return File::Spec::Functions::abs2rel( $file, $base );
}

sub get_current_directory {
    return File::Spec::Functions::curdir();
}

sub get_strftime {
    return strftime '%H:%M:%S', gmtime;
}

sub get_strfdate {
    return strftime '%Y-%m-%d', gmtime;
}

1;

__END__
