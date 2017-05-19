package Scar::Util::Log;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use warnings FATAL => 'all';

# Scar modules
use Scar qw( get_strftime get_strfdate implode_path );

# Module version
our $VERSION = 0.01;

# Active log directory
our $DIRECTORY = get_strfdate();

# Default exports
our @EXPORT = qw( log_info log_warn log_error log_debug );

sub log_error {
    my ($message) = @_;
    _write_to_logfile( 'error.log', $message );
    print get_strftime() . " ERROR: $message";
    croak;
}

sub log_info {
    my ($message) = @_;
    _write_to_logfile( 'scar.log', $message );
    print get_strftime() . "  INFO: $message";
    return 1;
}

sub log_warn {
    my ($message) = @_;
    _write_to_logfile( 'scar.log', "Warning: $message" );
    print get_strftime() . "  WARN: $message";
    return 1;
}

sub log_debug {
    my ($message) = @_;
    _write_to_logfile( 'debug.log', $message );
    print get_strftime() . " DEBUG: $message";
    return 1;
}

sub _write_to_logfile {
    my ( $logfile, $message ) = @_;
    if ( !-d $DIRECTORY ) { croak 'No output directory defined' }
    open my $logfile_handler, '>>:encoding(utf8)',
        implode_path( $DIRECTORY, $logfile )
        or croak;
    print {$logfile_handler} get_strftime() . ": $message\n";
    close $logfile_handler;
    return 1;
}

1;

__END__
