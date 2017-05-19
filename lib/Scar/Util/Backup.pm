package Scar::Util::Backup;

# Standard pragmas
use utf8;
use strict;
use base qw( Exporter );
use warnings FATAL => 'all';

# Standard modules
use Carp qw( croak );

# Scar modules
use Scar qw( get_strfdate explode_path implode_path );
use Scar::Util::Log;

# Module version
our $VERSION = 0.01;

# Active backup directory
our $DIRECTORY = get_strfdate();

# Default exports
our @EXPORT = qw( make_file_backup );

sub make_file_backup {
    my ($source_file) = @_;
    my @source_file_components = explode_path($source_file);
    my $destination_file
        = implode_path( $DIRECTORY, $source_file_components[2] );
    if ( !-f $destination_file ) {
        _copy_file( $source_file, $destination_file );
    }
    return -f $destination_file;
}

sub _copy_file {
    my ( $source_file, $destination_file ) = @_;
    my @source_file_contents;

    open my $input_handler, '<:raw', $source_file or croak;
    {
        while ( my $source_file_line = <$input_handler> ) {
            push @source_file_contents, $source_file_line;
        }
    }
    close $input_handler;

    open my $output_handler, '>:raw', $destination_file or croak;
    {
        for my $source_file_line (@source_file_contents) {
            print {$output_handler} $source_file_line;
        }
    }
    close $output_handler;

    return 1;
}

1;

__END__
