#!/bin/env perl
# ------------------------------------------------------------------------------
# NAME
#   install_test.pl
#
# SYNOPSIS
#   install_test.pl [options] args
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

# Standard pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard modules
use POSIX;
use File::Copy;
use Getopt::Long;
use File::Spec::Functions;

# Development module
use Data::Dumper;

# Vesion
our $VERSION = 1.40;

# Require root
my $login = ( getpwuid $> );
die "must run as root" if $login ne 'root';

# Installation
my $installer = SCARInstallTest->new();
$installer->prepare_installation;
$installer->install_files;
$installer->write_configuration;
move( "/tmp/scar_install.log", $installer->{directories}->{logs} );
print Data::Dumper::Dumper($installer);

package SCARInstallTest;

# ------------------------------------------------------------------------------
# SYNOPSIS
#   new
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub new {
    my ($class) = @_;
    my @uname = POSIX::uname();
    my $os_type    = "RHEL" if $uname[2] =~ /\.el\d\.x86_64$/;
    my $os_version = $1     if $uname[2] =~ /\.el(\d)\.x86_64$/;
    my $self       = bless {
        os => {
            type    => $os_type,
            version => $os_version,
        },
        healing     => { enabled => 0, },
        directories => {
            base      => "/SCAR",
            bin       => "bin",
            lib       => "lib",
            temp      => "tmp",
            logs      => "logs",
            backups   => "backups",
            reports   => "reports",
            plugins   => "plugins",
            templates => "templates",
        },
        output => {
            debug => 0,
            quiet => 0,
        }
    }, $class;

    Getopt::Long::GetOptions(
        'base=s'         => \$self->{directories}->{base},
        'logs=s'         => \$self->{directories}->{logs},
        'bin=s'          => \$self->{directories}->{bin},
        'lib=s'          => \$self->{directories}->{lib},
        'backups=s'      => \$self->{directories}->{backups},
        'reports=s'      => \$self->{directories}->{reports},
        'plugins=s'      => \$self->{directories}->{plugins},
        'templates=s'    => \$self->{directories}->{templates},
        'enable-healing' => \$self->{healing}->{enabled},
        'debug|d'        => \$self->{output}->{debug},
        'quiet|q'        => \$self->{output}->{quiet},
        'test=s'         => sub {
            $Data::Dumper::Varname = "Result";
            if ( my $sub_ref = $self->can( $_[1] ) ) {
                print Data::Dumper::Dumper( $self->$sub_ref(@ARGV) );
            }
        },
    );

    return $self;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub prepare_installation {
    my ($self) = @_;
    die "The base directory must be an absolute path\n"
        unless $self->{directories}->{base} =~ /^\//;
    die "You cannot set both -d [--debug] and -q [--quiet]"
        if $self->{output}->{debug} && $self->{output}->{quiet};
    while ( my ( $type, $dir ) = each %{ $self->{directories} } ) {
        unless ( $dir =~ /^\// ) {
            my $root_directory = $self->{directories}->{base};
            my $absolute_path
                = File::Spec::Functions::catdir( $root_directory, $dir );
            $self->{directories}->{$type} = $absolute_path;
        }
        if ( !-d $self->{directories}->{$type} ) {
            mkdir $self->{directories}->{$type};
            $self->_info("Directory created: $self->{directories}->{$type}");
        }
    }
    if ( !-d "$self->{directories}->{lib}/SCAR" ) {
        mkdir "$self->{directories}->{lib}/SCAR";
        $self->_info("Directory created: $self->{directories}->{lib}/SCAR");
    }
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   install_files
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub install_files {
    my ($self) = @_;
    my $os_prefix = $self->{os}->{type} . $self->{os}->{version};
    foreach my $installed_file (
        $self->copy_contents( "lib", $self->{directories}->{lib} ) )
    {
        $self->_info("Installed $installed_file");
    }
    foreach my $installed_file (
        $self->copy_contents(
            "lib/SCAR", "$self->{directories}->{lib}/SCAR"
        )
        )
    {
        $self->_info("Installed $installed_file");
    }
    foreach my $installed_file (
        $self->copy_contents(
            "plugins/$os_prefix", $self->{directories}->{plugins}
        )
        )
    {
        $self->_info("Installed $installed_file");
    }
    foreach my $installed_file (
        $self->copy_contents(
            "templates/$os_prefix", $self->{directories}->{templates}
        )
        )
    {
        $self->_info("Installed $installed_file");
    }
    foreach my $installed_file (
        $self->copy_contents(
            "bin/$os_prefix.pl", $self->{directories}->{bin}
        )
        )
    {
        $self->_info("Installed $installed_file");
    }
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub list_contents {
    my ( $self, $directory ) = @_;

    die "Unable to list contents for '$directory': not a valid directory\n"
        if !-d $directory;
    opendir( my $dh, $directory );
    my @contents = grep { -f File::Spec::Functions::catdir( $directory, $_ ) }
        readdir($dh);
    close $dh;

    foreach my $item (@contents) {
        $item = File::Spec::Functions::catdir( $directory, $item );
    }

    return @contents;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub copy_contents {
    my ( $self, $source, $destination ) = @_;

    die "Unable to copy files to '$destination': not a valid directory\n"
        if !-d $destination;
    my @contents = $self->list_contents($source) if -d $source;
    @contents = ($source) if -f $source;
    foreach my $item (@contents) {
        my @path_info = File::Spec::Functions::splitpath($item);
        my $destination_file
            = File::Spec::Functions::catdir( $destination, $path_info[2] );
        open( my $input, "<:raw", $item )
            || die "Unable to open '$item': $!\n";
        open( my $output, ">:raw", $destination_file )
            || die "Unable to open '$destination_file': $!\n";
        while (<$input>) {
            print $output $_;
        }
        close $input;
        close $output;
        $item = $destination_file;
    }
    return @contents;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub write_configuration {
    my ($self) = @_;
    my $file = "$self->{directories}->{bin}/config.ini";
    die "No file name provided" if ( !defined $file or ( $file eq '' ) );
    my ($string) = $self->configuration_string();

    return undef unless defined $string;

    open( my $fh, ">:encoding(utf8)", $file )
        || die "Failed to open file '$file': $!";
    print $fh $string;
    close $fh;

    $self->_info("Configuration created: $file");
    return 1;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#
# DESCRIPTION
#
# ARGUMENTS
#
# ------------------------------------------------------------------------------

sub configuration_string {
    my ($self)     = @_;
    my ($contents) = '';

    for my $section (
        sort { ( ( $b eq '_' ) <=> ( $a eq '_' ) ) || ( $a cmp $b ) }
        keys %$self
        )
    {
        die "Illegal whitespace in section name '$section'"
            if $section =~ /(?:^\s|\n|\s$)/s;
        my $block = $self->{$section};
        $contents .= "\n" if length $contents;
        $contents .= "[$section]\n" unless $section eq '_';
        for my $property ( sort keys %$block ) {
            die "Illegal newlines in property '$section.$property'"
                if $block->{$property} =~ /(?:\012|\015)/s;
            $contents .= "$property=$block->{$property}\n";
        }
    }

    return $contents;
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   &_info($message);
#
# DESCRIPTION
#   Prints an informational message to the user and adds it to the install log
#
# ARGUMENTS
#   $message    - the message to print and log
#
# ------------------------------------------------------------------------------

sub _info {
    my ( $self, $message ) = @_;
    $message = $self->hhmmss . "  INFO: $message\n";
    my $install_log = "/tmp/scar_install.log";
    open( my $fh, ">>:utf8", $install_log )
        || die "Could not open '$install_log': $1\n";
    print $fh $self->yyyymmdd . " $message";
    print $message unless $self->{output}->{quiet};
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub hhmmss {
    return POSIX::strftime '%H:%M:%S', gmtime();
}

# ------------------------------------------------------------------------------
# SYNOPSIS
#   hhmmss
#
# DESCRIPTION
#
# ------------------------------------------------------------------------------

sub yyyymmdd {
    return POSIX::strftime '%Y-%m-%d', gmtime();
}

# ------------------------------------------------------------------------------

__END__
