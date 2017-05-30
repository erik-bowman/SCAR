package Scar::Util::Backup;

=comment

Perl Core Pragmas

=cut

use utf8;
use strict;
use base qw( Exporter );
use warnings FATAL => 'all';

=comment

Perl Core Modules

=cut

use POSIX ();
use Carp qw( croak );
use File::Spec::Functions;
use English qw{ -no_matched_vars };

=comment

Scar Local Modules

=cut

use Scar::Util::Log;

=comment

Module Version

=cut

our $VERSION = 1.4.0;

=comment

Module Exports

=cut

our @EXPORT = qw( create_backup );

=comment

Create file backup subroutine

=cut

sub create_backup {
    my ($source) = @ARG;

    my $directory
        = '/SCAR/backups/' . POSIX::strftime( '%Y-%m-%d', gmtime() );

    if ( not -d $directory ) {

        log_debug("Creating backup directory '$directory'");

        mkdir $directory
            or croak "Unable to create directory '$directory': $OS_ERROR";
    }

    my @source_components = File::Spec::Functions::splitpath($source);

    my $destination_file
        = File::Spec::Functions::catdir( $directory, $source_components[2] );

    if ( -f $destination_file ) {

        log_debug("A backup of '$source' already exists: $destination_file");

        return 1;
    }

    log_info("Creating backup of '$source'");

    open my $input_handler, '<:raw', $source
        or croak "Unable to open file '$source' for reading: $OS_ERROR";
    {

        open my $output_handler, '>:raw', $destination_file
            or croak "Unable to write to file '$destination_file': $OS_ERROR";
        {
            while ( my $source_file_line = <$input_handler> ) {
                print {$output_handler} $source_file_line;
            }
        }
        close $output_handler;

    }
    close $input_handler;

    log_info("Backup created: $destination_file");

    return 1;
}

1;

__END__
