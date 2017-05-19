package Scar::Util::Log;

# Standard modules
use utf8;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use warnings FATAL => 'all';

# Scar modules
use Scar qw( FTIME FDATE IMPLODEPATH );

# Module version
our $VERSION = 0.01;

# Active log directory
our $DIRECTORY;

# Default exports
our @EXPORT = qw( INFO WARN ERROR DEBUG );

sub ERROR {
    my ($MESSAGE) = @_;
    WRITELOG( 'error.log', $MESSAGE );
    print FTIME() . " ERROR: $MESSAGE";
    croak;
}

sub INFO {
    my ($MESSAGE) = @_;
    WRITELOG( 'scar.log', $MESSAGE );
    print FTIME() . "  INFO: $MESSAGE";
    return 1;
}

sub WARN {
    my ($MESSAGE) = @_;
    WRITELOG( 'scar.log', "Warning: $MESSAGE" );
    print FTIME() . "  WARN: $MESSAGE";
    return 1;
}

sub DEBUG {
    my ($MESSAGE) = @_;
    WRITELOG( 'debug.log', $MESSAGE );
    print FTIME() . " DEBUG: $MESSAGE";
    return 1;
}

sub WRITELOG {
    my ( $FILE, $MESSAGE ) = @_;
    if ( !-d $DIRECTORY ) { croak 'No output directory defined' }
    open my $FH, '>>:encoding(utf8)', IMPLODEPATH( $DIRECTORY, $FILE )
        or croak;
    print {$FH} FTIME() . ": $MESSAGE\n";
    close $FH;
    return 1;
}

1;

__END__
