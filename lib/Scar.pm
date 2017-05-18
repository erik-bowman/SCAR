package Scar;

use utf8;
use 5.008;
use strict;
use Carp qw( croak );
use base qw( Exporter );
use POSIX qw( strftime );
use File::Spec::Functions;
use warnings FATAL => 'all';

our $VERSION = 0.01;

our @EXPORT_OK
    = qw( AWK GREP PARSE SERVICE CHKCONFIG IMPLODEPATH EXPLODEPATH FTIME FDATE );

sub IMPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::catdir(@PARTS);
}

sub EXPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::splitpath(@PARTS);
}

sub FTIME {
    return strftime '%H:%M:%S', gmtime;
}

sub FDATE {
    return strftime '%Y-%m-%d', gmtime;
}

sub RUN {
    my ( $BIN, $ARGS ) = @_;
    my @RESULTS;

    open my $RUN, " $BIN $ARGS 2>&1 |" or croak "Could not run $BIN\n";
    {

        while ( my $RESULT = <$RUN> ) {
            push @RESULTS, $RESULT;
        }

    }
    close $RUN;

    return @RESULTS;
}

sub AWK {
    my ($ARGS) = @_;
    return RUN( '/bin/awk', $ARGS );
}

sub GREP {
    my ($ARGS) = @_;
    return join "\n", RUN( '/bin/grep', $ARGS );
}

sub SERVICE {
    my ($ARGS) = @_;
    return join "\n", RUN( '/sbin/service', $ARGS );
}

sub CHKCONFIG {
    my ($ARGS) = @_;
    return RUN( '/sbin/chkconfig', $ARGS );
}

sub PARSE {
    my ( $REGEX, $FILE ) = @_;
    my @RESULTS;

    open my $FH, '<:encoding(utf8)', $FILE or croak 'Could not parse file';
    {

        while ( my $LINE = <$FH> ) {

            if ( $LINE =~ /$REGEX/msx ) {
                push @RESULTS, $&;
            }

        }

    }
    close $FH;

    return @RESULTS;
}

1;

__END__

=pod

=head1 NAME

Scar - Exports core methods used throughout the package.


=head1 VERSION

This docuemntation refers to Scar version 1.4.0


=head1 USAGE

    use Scar;

    $PATH       = IMPLODEPATH( @COMPONENTS );
    @COMPONENTS = EXPLODEPATH( $PATH );
    $DATESTRING = FDATE();
    $TIMESTRING = FTIME();


=head1 DESCRIPTION

This is the core module for Security Compliance and Remediation aka Scar.
Exports methods used ubiquitously throughout Scar by default;


=head1 OPTIONS


=head1 REQUIRED ARGUMENTS


=head1 DIAGNOSTICS

=head1 EXIT STATUS


=head1 CONFIGURATION


=head1 DEPENDENCIES

Perl 5.008, Exporter

=head1 INCOMPATIBILITIES


=head1 BUGS AND LIMITATIONS

There are no known bugs in this module.
Please report problems to Erk Bowman (erik.bowman@icsinc.com)
Patches are welcome.


=head1 AUTHOR

Erik Bowman (erik.bowman@icsinc.com)


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2017 Erik Bowman (erik.bowman@icsinc.com). All rights reserved.

This module is private software; do not redistribute it and/or
modify it without proper authorization or approval.

This program is distributed in the hopes that it wil be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.


=cut
