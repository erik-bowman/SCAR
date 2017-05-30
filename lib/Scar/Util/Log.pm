package Scar::Util::Log;

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

Module Version

=cut

our $VERSION = 1.4.0;

=comment

Module Exports

=cut

our @EXPORT = qw{ log_info log_warn log_error log_debug log_change };

sub log_error {
    my ($message) = @ARG;
    _write_to_logfile( 'error.log', $message );
    print POSIX::strftime( '%H:%M:%S', gmtime() ) . " ERROR: $message\n";
    croak;
}

sub log_info {
    my ($message) = @ARG;
    _write_to_logfile( 'scar.log', $message );
    print POSIX::strftime( '%H:%M:%S', gmtime() ) . "  INFO: $message\n";
    return;
}

sub log_warn {
    my ($message) = @ARG;
    _write_to_logfile( 'scar.log', "Warning: $message" );
    print POSIX::strftime( '%H:%M:%S', gmtime() ) . "  WARN: $message\n";
    return;
}

sub log_debug {
    my ($message) = @ARG;
    _write_to_logfile( 'debug.log', $message );
    if ($main::debug) {
        print POSIX::strftime( '%H:%M:%S', gmtime() ) . " DEBUG: $message\n";
    }
    return;
}

sub log_change {
    my ($message) = @ARG;
    _write_to_logfile( 'change_list.log', $message );
    return;
}

sub _write_to_logfile {
    my ( $logfile, $message ) = @ARG;

    my $directory = '/SCAR/logs/' . POSIX::strftime( '%Y-%m-%d', gmtime() );
    if ( !-d $directory ) {
        mkdir $directory;
    }

    open my $logfile_handler, '>>:encoding(utf8)', "$directory/$logfile"
        or croak "Could not open file '$directory/$logfile': $OS_ERROR";
    {

        print {$logfile_handler} POSIX::strftime( '%H:%M:%S', gmtime() )
            . ": $message\n";
    }
    close $logfile_handler;

    return;
}

1;

__END__
