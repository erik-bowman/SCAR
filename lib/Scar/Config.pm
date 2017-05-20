package Scar::Config;

# Standard pragmas
use strict;
use 5.008001;
use warnings FATAL => 'all';

# Standard modules
use Carp qw( croak );
use English qw( -no_match_vars );

# Module version
our $VERSION = '2.23';

sub new {
    my ($class) = @_;
    return bless {}, $class;
}

sub open_config_file {
    my ( $self, $file, $encoding ) = @_;

    if ( !defined $file || ( $file eq q{} ) ) {
        croak 'No file name provided';
    }

    $encoding = $encoding ? "<:$encoding" : '<';
    local $INPUT_RECORD_SEPARATOR = undef;

    open my $config_file_handler, $encoding, $file
        or croak "Failed to open file '$file' for reading: $OS_ERROR";
    my $contents = <$config_file_handler>;
    close $config_file_handler;

    if ( !defined $contents ) {
        croak "Reading from '$file' returned undef";
    }

    return $self->_convert_from_string($contents);
}

sub _convert_from_string {
    my ( $self, $config_file_entries ) = @_;

    if ( !defined $config_file_entries ) {
        return 0;
    }

    my $ns             = '_';
    my $line_counter   = 0;
    my @config_entries = split /(?:\015{1,2}\012|[\015\012])/msx,
        $config_file_entries;

    foreach my $config_entry (@config_entries) {
        $line_counter++;

        if ( $config_entry =~ /^\s*(?:[\#\;]|$)/msx ) {
            next;
        }

        $config_entry = !s/\s\;\s.+$//msxg;

        if ( $config_entry =~ /^\s*\[\s*(.+?)\s*\]\s*$/msx ) {
            $self->{ $ns = $1 } ||= {};
            next;
        }

        if ( $config_entry =~ /^\s*([^=]+?)\s*=\s*(.*?)\s*$/msx ) {
            $self->{$ns}->{$1} = $2;
            next;
        }

        croak "Syntax error at line $line_counter: '$config_entry'";
    }

    return $self;
}

sub save_config_file {
    my ( $self, $file, $encoding ) = @_;

    if ( !defined $file || $file eq q{} ) {
        croak 'No file name provided';
    }

    $encoding = $encoding ? ">:$encoding" : '>';

    my ($string) = $self->_convert_to_string;

    if ( !defined $string ) {
        return 0;
    }

    open my $config_file_handler, $encoding, $file
        or croak "Failed to open file '$file' for writing: $OS_ERROR";
    print {$config_file_handler} $string;
    close $config_file_handler;

    return 1;
}

sub _convert_to_string {
    my ($self)     = @_;
    my ($contents) = q{};

    for my $section (
        sort { ( ( $a eq '_' ) <=> ( $b eq '_' ) ) || ( $a cmp $b ) }
        keys %{$self}
        )
    {

        if ( $section =~ /(?:^\s|\n|\s$)/msx ) {
            croak "Illegal whitespace in section name '$section'";
        }

        my $block = $self->{$section};

        if ( length $contents ) {
            $contents .= "\n";
        }

        if ( $section ne '_' ) {
            $contents .= "[$section]\n";
        }

        for my $property ( sort keys %{$block} ) {

            if ( $block->{$property} =~ /(?:[\012\015])/msx ) {
                croak "Illegal newlines in property '$section.$property'";
            }

            $contents .= "$property=$block->{$property}\n";
        }

    }

    return $contents;
}

1;

__END__
