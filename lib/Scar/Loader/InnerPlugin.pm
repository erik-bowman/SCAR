package Scar::Loader::InnerPlugin;

use strict;
use warnings FATAL => 'all';

use Exporter 5.57 'import';

use if $] > 5.017, 'deprecate';

our $VERSION   = '0.4';
our @EXPORT_OK = qw(list_packages);

sub list_packages {
    my $pack = shift;
    $pack .= "::" unless $pack =~ m!::$!;

    no strict 'refs';
    my @packs;
    my @stuff = grep !/^(main|)::$/, keys %{$pack};
    for my $cand ( grep /::$/, @stuff ) {
        $cand =~ s!::$!!;
        my @children = list_packages( $pack . $cand );

        push @packs, "$pack$cand"
            unless $cand =~ /^::/
                || !__PACKAGE__->_loaded( $pack . $cand );
        push @packs, @children;
    }
    return grep { $_ !~ /::(::ISA::CACHE|SUPER)/ } @packs;
}

sub _loaded {
    my ( $class, $name ) = @_;

    no strict 'refs';

    return 1 if defined ${"${name}::VERSION"};
    return 1 if @{"${name}::ISA"};

    foreach ( keys %{"${name}::"} ) {
        next if substr( $_, -2, 2 ) eq '::';
        return 1 if defined &{"${name}::$_"};
    }

    my $filename = join( '/', split /(?:'|::)/, $name ) . '.pm';
    return 1 if defined $INC{$filename};

    '';
}

1;

__END__
