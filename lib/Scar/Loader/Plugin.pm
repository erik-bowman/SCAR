package Scar::Loader::Plugin;

use strict;
use File::Find ();
use File::Basename;
use Scar::Loader::InnerPlugin;
use File::Spec::Functions;
use vars qw($VERSION $MR);
use warnings FATAL => 'all';
use Carp qw(croak carp confess);
use English qw{ -no_match_vars };

use if $] > 5.017, 'deprecate';

$VERSION = '5.2';

BEGIN {
    eval { require Module::Runtime };
    unless ($EVAL_ERROR) {
        Module::Runtime->import('require_module');
    }
    else {
        *require_module = sub {
            my $module = shift;
            my $path   = $module . '.pm';
            $path =~ s{::}{/}msxg;
            require $path;
        };
    }
}

#@method
#@returns Scar::Loader::Plugin
sub new {
    my $class = shift;
    my %opts  = @ARG;

    return bless \%opts, $class;

}

#@method
sub plugins {
    my $self = shift;
    my @args = @ARG;

    if ( $self->{'inner'} ) {
        $self->{'require'} = 1;
    }

    my $filename = $self->{'filename'};
    my $pkg      = $self->{'package'};

    $self->_setup_exceptions;

    for (qw(search_path search_dirs)) {
        if ( exists $self->{$ARG} && !ref( $self->{$ARG} ) ) {
            $self->{$ARG} = [ $self->{$ARG} ];
        }
    }

    $self->{'search_path'} ||= ["${pkg}::Plugin"];

    $self->{'on_require_error'} ||= sub {
        my ( $plugin, $err ) = @ARG;
        carp "Couldn't require $plugin : $err";
        return 0;
    };
    $self->{'on_instantiate_error'} ||= sub {
        my ( $plugin, $err ) = @ARG;
        carp "Couldn't instantiate $plugin: $err";
        return 0;
    };

    unless ( exists $self->{'follow_symlinks'} ) {
        $self->{'follow_symlinks'} = 1;
    }

    my @SEARCHDIR
        = exists $INC{'blib.pm'}
        && defined $filename
        && $filename =~ m!(^|/)blib/!msx
        && !$self->{'force_search_all_paths'} ? grep {/blib/ms} @INC : @INC;

    unshift @SEARCHDIR, @{ $self->{'search_dirs'} }
        if defined $self->{'search_dirs'};

    my @tmp = @INC;
    unshift @tmp, @{ $self->{'search_dirs'} || [] };
    if ( defined $self->{'search_dirs'} ) {
        local @INC = @tmp;
    }

    my @plugins = $self->search_directories(@SEARCHDIR);

    for ( @{ $self->{'search_path'} } ) {
        push @plugins, $self->handle_inc_hooks( $ARG, @SEARCHDIR );
    }
    for ( @{ $self->{'search_path'} } ) {
        push @plugins, $self->handle_innerpackages($ARG);
    }

    unless (@plugins) {
        return ();
    }

    my %plugins;
    for (@plugins) {
        unless ( $self->_is_legit($ARG) ) {
            next;
        }
        $plugins{$ARG} = 1;
    }
    my $method = 'new';
    my @objs   = ();
    foreach my $package ( sort keys %plugins ) {
        unless ( $package->can($method) ) {
            next;
        }
        my $obj = eval { $package->$method(@ARG) };
        if ($EVAL_ERROR) {
            $self->{'on_instantiate_error'}->( $package, $EVAL_ERROR );
        }
        if ($obj) {
            push @objs, $obj;
        }
    }
    return @objs;
}

#@method
sub _setup_exceptions {
    my $self = shift;

    my %only;
    my %except;
    my $only;
    my $except;

    if ( defined $self->{'only'} ) {
        if ( ref( $self->{'only'} ) eq 'ARRAY' ) {
            %only = map { $_ => 1 } @{ $self->{'only'} };
        }
        elsif ( ref( $self->{'only'} ) eq 'Regexp' ) {
            $only = $self->{'only'};
        }
        elsif ( ref( $self->{'only'} ) eq q{} ) {
            $only{ $self->{'only'} } = 1;
        }
    }

    if ( defined $self->{'except'} ) {
        if ( ref( $self->{'except'} ) eq 'ARRAY' ) {
            %except = map { $_ => 1 } @{ $self->{'except'} };
        }
        elsif ( ref( $self->{'except'} ) eq 'Regexp' ) {
            $except = $self->{'except'};
        }
        elsif ( ref( $self->{'except'} ) eq q{} ) {
            $except{ $self->{'except'} } = 1;
        }
    }
    $self->{_exceptions}->{only_hash}   = \%only;
    $self->{_exceptions}->{only}        = $only;
    $self->{_exceptions}->{except_hash} = \%except;
    $self->{_exceptions}->{except}      = $except;
    return;
}

#@method
sub _is_legit {
    my $self   = shift;
    my $plugin = shift;
    my %only   = %{ $self->{_exceptions}->{only_hash} || {} };
    my %except = %{ $self->{_exceptions}->{except_hash} || {} };
    my $only   = $self->{_exceptions}->{only};
    my $except = $self->{_exceptions}->{except};
    my $depth  = () = split /::/msx, $plugin, -1;

    if ( keys %only && !$only{$plugin} ) {
        return 0;
    }
    unless ( !defined $only || $plugin =~ m{$only}msx ) {
        return 0;
    }

    return 0 if keys %except && $except{$plugin};
    return 0 if defined $except && $plugin =~ m{$except}msx;

    return 0 if defined $self->{max_depth} && $depth > $self->{max_depth};
    return 0 if defined $self->{min_depth} && $depth < $self->{min_depth};

    return 1;
}

#@method
sub search_directories {
    my $self      = shift;
    my @SEARCHDIR = @ARG;

    my @plugins;
    foreach my $dir (@SEARCHDIR) {
        push @plugins, $self->search_paths($dir);
    }
    return @plugins;
}

#@method
sub search_paths {
    my $self = shift;
    my $dir  = shift;
    my @plugins;

    my $file_regex = $self->{'file_regex'} || qr/[.]pm$/msx;

    foreach my $searchpath ( @{ $self->{'search_path'} } ) {
        my $sp = File::Spec::Functions::catdir( $dir,
            ( split /::/msx, $searchpath ) );

        next unless -e $sp && -d _;

        my @files = $self->find_files($sp);

        foreach my $file (@files) {
            next unless ($file) = ( $file =~ /(.*$file_regex)$/msx );
            my ( $name, $directory, $suffix )
                = fileparse( $file, $file_regex );

            next
                if !$self->{include_editor_junk}
                && $self->_is_editor_junk($name);

            $directory = File::Spec::Functions::abs2rel( $directory, $sp );

            my @pkg_dirs = ();
            if ( $name eq lc $name || $name eq uc $name ) {
                my $pkg_file
                    = File::Spec::Functions::catfile( $sp, $directory,
                    "$name$suffix" );
                open my $file_handler, '<:encoding(utf8)', "$pkg_file"
                    or die "search_paths: Can't open $pkg_file: $OS_ERROR";
                my $in_pod = 0;
                my @contents;
                while ( my $line = <$file_handler> ) {
                    push @contents, $line;
                }
                close $file_handler;

                foreach my $line (@contents) {
                    $in_pod = 1 if $line =~ m/^=\w/msx;
                    $in_pod = 0 if $line =~ /^=cut/msx;
                    next if $in_pod || $line =~ /^=cut/msx;
                    next if $line =~ /^\s*#/msx;
                    if ( $line =~ m/^\s*package\s+(.*::)?($name)\s*;/imsx ) {
                        @pkg_dirs = split /::/msx, $1 if defined $1;
                        $name = $2;
                        last;
                    }
                }
            }

            $directory =~ s/^[[:lower:]]://imsx
                if $OSNAME =~ /MSWin32|dos/msx;
            my @dirs = ();
            if ($directory) {
                ($directory) = ( $directory =~ /(.*)/msx );
                @dirs = grep( length($ARG),
                    File::Spec::Functions::splitdir($directory) )
                    unless $directory eq File::Spec::Functions::curdir();
                for my $d ( reverse @dirs ) {
                    my $pkg_dir = pop @pkg_dirs;
                    last unless defined $pkg_dir;
                    $d =~ s/\Q$pkg_dir\E/$pkg_dir/imsx;
                }
            }
            else {
                $directory = q{};
            }
            my $plugin = join q{::}, $searchpath, @dirs, $name;

            next unless $plugin =~ m{(?:[[:lower:]\d]+)[[:lower:]\d]*}imsx;

            $self->handle_finding_plugin( $plugin, \@plugins );
        }

        push @plugins, $self->handle_innerpackages($searchpath);
    }

    return @plugins;
}

#@method
sub _is_editor_junk {
    my $self = shift;
    my $name = shift;

    return 1 if $name =~ /~$/msx;
    return 1 if $name =~ /^[.]#/msx;
    return 1 if $name =~ /[.]sw[po]$/msx;

    return 0;
}

#@method
sub handle_finding_plugin {
    my $self    = shift;
    my $plugin  = shift;
    my $plugins = shift;
    my $no_req  = shift || 0;

    return unless $self->_is_legit($plugin);
    unless ( defined $self->{'instantiate'} || $self->{'require'} ) {
        push @{$plugins}, $plugin;
        return;
    }

    $self->{before_require}->($plugin) || return
        if defined $self->{before_require};
    unless ($no_req) {
        my $tmp = $EVAL_ERROR;
        my $res = eval { require_module($plugin) };
        my $err = $EVAL_ERROR;
        $EVAL_ERROR = $tmp;
        if ($err) {
            if ( defined $self->{on_require_error} ) {
                $self->{on_require_error}->( $plugin, $err ) || return;
            }
            else {
                return;
            }
        }
    }
    $self->{after_require}->($plugin) || return
        if defined $self->{after_require};
    push @{$plugins}, $plugin;
}

sub find_files {
    my $self        = shift;
    my $search_path = shift;
    my $file_regex  = $self->{'file_regex'} || qr/[.]pm$/msx;

    my @files = ();
    {
        local $ARG;
        File::Find::find(
            {   no_chdir => 1,
                follow   => $self->{'follow_symlinks'},
                wanted   => sub {
                    return unless $File::Find::name =~ /$file_regex/msx;
                    ( my $path = $File::Find::name ) =~ s{^\\./}{}msx;
                    push @files, $path;
                }
            },
            $search_path
        );
    }
    return @files;

}

#@method
sub handle_inc_hooks {
    my $self      = shift;
    my $path      = shift;
    my @SEARCHDIR = @ARG;

    my @plugins;
    for my $dir (@SEARCHDIR) {
        next unless ref $dir && eval { $dir->can('files') };

        foreach my $plugin ( $dir->files ) {
            $plugin =~ s/\.pm$//msx;
            $plugin =~ s{/}{::}msxg;
            next unless $plugin =~ m{^${path}::}msx;
            $self->handle_finding_plugin( $plugin, \@plugins );
        }
    }
    return @plugins;
}

#@method
sub handle_innerpackages {
    my $self = shift;
    return () if exists $self->{inner} && !$self->{inner};

    my $path = shift;
    my @plugins;

    foreach my $plugin ( Scar::Loader::InnerPlugin::list_packages($path) ) {
        $self->handle_finding_plugin( $plugin, \@plugins, 1 );
    }
    return @plugins;

}

1;

__END__
