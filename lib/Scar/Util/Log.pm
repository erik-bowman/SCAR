package Scar::Util::Log;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matches_vars };

# Local Modules
use Scar qw( get_strftime get_strfdate implode_path );

# Module Hierarchy
use base qw{ Exporter };

# Module version
our $VERSION = 1.40;

# Module Exports
our @EXPORT = qw( log_info log_warn log_error log_debug );

sub log_error {
    my ($message) = @ARG;
    _write_to_logfile( 'error.log', $message );
    print get_strftime() . " ERROR: $message\n";
    croak;
}

sub log_info {
    my ($message) = @ARG;
    _write_to_logfile( 'scar.log', $message );
    print get_strftime() . "  INFO: $message\n";
    return 1;
}

sub log_warn {
    my ($message) = @ARG;
    _write_to_logfile( 'scar.log', "Warning: $message" );
    print get_strftime() . "  WARN: $message\n";
    return 1;
}

sub log_debug {
    my ($message) = @ARG;
    _write_to_logfile( 'debug.log', $message );
    if ($main::Debug) {
        print get_strftime() . " DEBUG: $message\n";
    }
    return 1;
}

sub _write_to_logfile {
    my ( $logfile, $message ) = @ARG;

    my $directory = '/SCAR/logs/' . get_strfdate();
    if ( !-d $directory ) {
        mkdir $directory;
    }

    open my $logfile_handler, '>>:encoding(utf8)', "$directory/$logfile"
        or croak "Could not open file '$directory/$logfile': $OS_ERROR";
    print {$logfile_handler} get_strftime() . ": $message\n";
    close $logfile_handler;
    return 1;
}

1;

__END__
