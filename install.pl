#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   install.pl
#
# SYNOPSIS
#   install.pl [options] args
#
# DESCRIPTION
#
#
# OPTIONS
#
#
# ARGUMENTS
#
#
# SEE ALSO
#
#
# AUTHOR
#   Erik Bowman (erik.bowman@icsinc.com)
#
# ------------------------------------------------------------------------------

# Standard modules
use utf8;
use strict;
use POSIX qw( strftime );
use File::Copy;
use Getopt::Long;
use Carp qw( croak );
use File::Spec::Functions;
use warnings FATAL => 'all';

# Vesion
our $VERSION = 1.40;

# Require root
my $LOGIN = ( getpwuid $> );
croak 'This installer must run as root' if $LOGIN ne 'root';

# Installation
my $INSTALLER = SCAR::Install->new();

$INSTALLER->PREPARE;
$INSTALLER->INSTALL;
$INSTALLER->WRITECONF;

move( '/tmp/scar_install.log', $INSTALLER->{directories}->{logs} );

package SCAR::Install;

use utf8;
use strict;
use POSIX qw( strftime uname );
use File::Copy;
use Getopt::Long;
use Carp qw( croak );
use File::Spec::Functions;
use warnings FATAL => 'all';

sub new {
    my ($class) = @_;
    my @UNAME = uname();
    my $OSTYPE    = $UNAME[2] =~ /\wel\d\wx86_64$/msx   ? 'RHEL' : 0;
    my $OSRELEASE = $UNAME[2] =~ /\wel(\d)\wx86_64$/msx ? $1     : 0;
    my $self      = bless {
        os => {
            type    => $OSTYPE,
            version => $OSRELEASE,
        },
        healing     => { enabled => 0, },
        directories => {
            base      => '/SCAR',
            bin       => 'bin',
            temp      => 'tmp',
            logs      => 'logs',
            backups   => 'backups',
            reports   => 'reports',
            plugins   => 'plugins',
            templates => 'templates',
        },
        output => {
            debug => 0,
            quiet => 0,
        }
    }, $class;

    GetOptions(
        'base=s'         => \$self->{directories}->{base},
        'logs=s'         => \$self->{directories}->{logs},
        'backups=s'      => \$self->{directories}->{backups},
        'reports=s'      => \$self->{directories}->{reports},
        'plugins=s'      => \$self->{directories}->{plugins},
        'templates=s'    => \$self->{directories}->{templates},
        'enable-healing' => \$self->{healing}->{enabled},
        'debug|d'        => \$self->{output}->{debug},
        'quiet|q'        => \$self->{output}->{quiet},
    );

    return $self;
}

sub PREPARE {
    my ($self) = @_;

    if ( $self->{directories}->{base} =~ /^\\/msx ) {
        croak "The base directory must be an absolute path\n";
    }

    if ( $self->{output}->{debug} && $self->{output}->{quiet} ) {
        croak "You cannot set both -d [--debug] and -q [--quiet]\n";
    }

    my $ROOTDIR = $self->{directories}->{base};

    while ( my ( $TYPE, $DIR ) = each %{ $self->{directories} } ) {

        if ( !$DIR =~ /^\//msx ) {
            my $ABSPATH = IMPLODEPATH( $ROOTDIR, $DIR );
            $self->{directories}->{$TYPE} = $ABSPATH;
        }

        if ( !-d $self->{directories}->{$TYPE} ) {
            mkdir $self->{directories}->{$TYPE};
            $self->INFO("Directory created: $self->{directories}->{$TYPE}");
        }

    }

    if ( !-d "$INC[0]/SCAR" ) {
        mkdir "$INC[0]/SCAR";
        $self->INFO("Directory created: $INC[0]/SCAR");
    }

    my $BIN = IMPLODEPATH( $ROOTDIR, 'bin' );

    if ( !-d $BIN ) {
        mkdir $BIN;
        $self->INFO("Directory created: $BIN");
    }

    return $self;
}

sub INSTALL {
    my ($self) = @_;
    my $PREFIX = $self->{os}->{type} . $self->{os}->{version};

    foreach my $INSTALLEDFILE ( $self->COPY( 'lib', $INC[0] ) ) {
        $self->INFO("Installed $INSTALLEDFILE");
    }

    foreach my $INSTALLEDFILE ( $self->COPY( 'lib/SCAR', "$INC[0]/SCAR" ) ) {
        $self->INFO("Installed $INSTALLEDFILE");
    }

    foreach my $INSTALLEDFILE (
        $self->COPY( "plugins/$PREFIX", $self->{directories}->{plugins} ) )
    {
        $self->INFO("Installed $INSTALLEDFILE");
    }

    foreach my $INSTALLEDFILE (
        $self->COPY( "templates/$PREFIX", $self->{directories}->{templates} )
        )
    {
        $self->INFO("Installed $INSTALLEDFILE");
    }

    foreach my $INSTALLEDFILE (
        $self->COPY( "bin/$PREFIX.pl", $self->{directories}->{bin} ) )
    {
        $self->INFO("Installed $INSTALLEDFILE");
    }

    return $self;
}

sub LIST {
    my ( $self, $DIR ) = @_;

    if ( !-d $DIR ) {
        croak "Unable to list contents for '$DIR': not a valid directory\n";
    }

    opendir my $DH, $DIR;
    my @CONTENTS = grep { -f IMPLODEPATH( $DIR, $_ ) } readdir $DH;
    close $DH;

    foreach my $ITEM (@CONTENTS) {
        $ITEM = IMPLODEPATH( $DIR, $ITEM );
    }

    return @CONTENTS;
}

sub COPY {
    my ( $self, $SOURCE, $DEST ) = @_;
    my @CONTENTS;

    if ( !-d $DEST ) {
        die "Unable to copy files to '$DEST': not a valid directory\n";
    }

    if ( -d $SOURCE ) {
        @CONTENTS = $self->LIST($SOURCE);
    }

    if ( -f $SOURCE ) {
        @CONTENTS = ($SOURCE);
    }

    foreach my $ITEM (@CONTENTS) {
        my @PATHINFO = EXPLODEPATH($ITEM);
        my $DESTFILE = IMPLODEPATH( $DEST, $PATHINFO[2] );

        open my $INPUT, '<:raw', $ITEM or croak "Unable to open '$ITEM'\n";
        open my $OUTPUT, '>:raw', $DESTFILE
            or croak "Unable to open '$DESTFILE'\n";
        while (<$INPUT>) {
            print {$OUTPUT} $_;
        }
        close $INPUT;
        close $OUTPUT;
        $ITEM = $DESTFILE;
    }

    return @CONTENTS;
}

sub WRITECONF {
    my ($self) = @_;
    my $ROOT = $self->{directories}->{base};
    my $FILE = IMPLODEPATH( $ROOT, 'bin', 'config.ini' );

    if ( !defined $FILE || $FILE eq '' ) {
        croak 'No file name provided';
    }

    my ($string) = $self->STRINGCONF();

    if ( !defined $string ) {
        return;
    }

    open my $FH, '>:encoding(utf8)',
        $FILE || croak "Failed to open file '$FILE'\n";
    print {$FH} $string;
    close $FH;

    $self->INFO("Configuration created: $FILE");
    return 1;
}

sub STRINGCONF {
    my ($self)     = @_;
    my ($CONTENTS) = '';

    for my $SECTION (
        sort { ( ( $b eq '_' ) <=> ( $a eq '_' ) ) || ( $a cmp $b ) }
        keys %{$self}
        )
    {
        if ( $SECTION =~ /(?:^\s|\n|\s$)/msx ) {
            croak "Illegal whitespace in section name '$SECTION'";
        }

        my $BLOCK = $self->{$SECTION};

        if ( length $CONTENTS ) {
            $CONTENTS .= "\n";
        }

        if ( !$SECTION eq '_' ) {
            $CONTENTS .= "[$SECTION]\n";
        }

        for my $PROPERTY ( sort keys %{$BLOCK} ) {

            if ( $BLOCK->{$PROPERTY} =~ /(?:[\012\015])/msx ) {
                croak "Illegal newlines in property '$SECTION.$PROPERTY'";
            }

            $CONTENTS .= "$PROPERTY=$BLOCK->{$PROPERTY}\n";
        }

    }

    return $CONTENTS;
}

sub INFO {
    my ( $self, $MESSAGE ) = @_;
    $MESSAGE = $self->FTIME . "  INFO: $MESSAGE\n";
    my $INSTALLLOG = '/tmp/scar_install.log';

    open my $FH, '>>:utf8', $INSTALLLOG
        or croak "Could not open '$INSTALLLOG': $1\n";
    print {$FH} $self->FDATE . " $MESSAGE";
    close $FH;

    if ( !$self->{output}->{quiet} ) {
        print $MESSAGE;
    }

    return $self;
}

sub FTIME {
    return strftime '%H:%M:%S', gmtime;
}

sub FDATE {
    return strftime '%Y-%m-%d', gmtime;
}

sub IMPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::catdir(@PARTS);
}

sub EXPLODEPATH {
    my @PARTS = @_;
    return File::Spec::Functions::splitpath(@PARTS);
}

1;

__END__
