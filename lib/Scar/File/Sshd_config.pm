package Scar::File::Sshd_config;

use strict;
use base qw{ Scar::File };
use warnings FATAL => 'all';

use Carp qw{ croak };
use English qw{ -no_match_vars };

our $VERSION = 0.01;

#@method
sub new {
    my ($class) = @ARG;
    my $self = bless {
        Ciphers                 => undef,
        Banner                  => undef,
        Protocol                => undef,
        IgnoreRhosts            => undef,
        PrintLastlog            => undef,
        PermitRootLogin         => undef,
        ClientAliveInterval     => undef,
        ClientAliveCountMax     => undef,
        PermitEmptyPasswords    => undef,
        PermitUserEnvironment   => undef,
        HostbasedAuthentication => undef,
    }, $class;

    my @file_contents;
    open my $file_handle, '<:encoding(utf8)', 'tests/test_data/sshd_config'
        or croak "$OS_ERROR";
    {
        while ( my $line = <$file_handle> ) {
            chomp $line;
            push @file_contents, $line;
        }
    }
    close $file_handle;

    foreach my $line (@file_contents) {
        if ( $line =~ /^Ciphers\s+(.*)$/imsx ) {
            $self->Ciphers($1);
        }
        if ( $line =~ /^Banner\s+(.*)$/imsx ) {
            $self->Banner($1);
        }
        if ( $line =~ /^Protocol\s+(.*)$/imsx ) {
            $self->Protocol($1);
        }
        if ( $line =~ /^IgnoreRhosts\s+(.*)$/imsx ) {
            $self->IgnoreRhosts($1);
        }
        if ( $line =~ /^PrintLastlog\s+(.*)$/imsx ) {
            $self->PrintLastlog($1);
        }
        if ( $line =~ /^PermitRootLogin\s+(.*)$/imsx ) {
            $self->PermitRootLogin($1);
        }
        if ( $line =~ /^ClientAliveInterval\s+(.*)$/imsx ) {
            $self->ClientAliveInterval($1);
        }
        if ( $line =~ /^ClientAliveCountMax\s+(.*)$/imsx ) {
            $self->ClientAliveCountMax($1);
        }
        if ( $line =~ /^PermitEmptyPasswords\s+(.*)$/imsx ) {
            $self->PermitEmptyPasswords($1);
        }
        if ( $line =~ /^PermitUserEnvironment\s+(.*)$/imsx ) {
            $self->PermitUserEnvironment($1);
        }
        if ( $line =~ /^HostbasedAuthentication\s+(.*)$/imsx ) {
            $self->HostbasedAuthentication($1);
        }

    }

    return $self;
}

#@method
sub Ciphers {
    my ( $self, @values ) = @ARG;
    if ( @ARG == 2 ) {
        foreach my $value (@values) {
            push @{ $self->{Ciphers} }, $value;
        }
    }
    return $self->{Ciphers};
}

#@method
sub Banner {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{Banner} = $value;
    }
    return $self->{Banner};
}

#@method
sub Protocol {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{Protocol} = $value;
    }
    return $self->{Protocol};
}

#@method
sub IgnoreRhosts {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{IgnoreRhosts} = $value;
    }
    return $self->{IgnoreRhosts};
}

#@method
sub PrintLastlog {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PrintLastlog} = $value;
    }
    return $self->{PrintLastlog};
}

#@method
sub PermitRootLogin {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitRootLogin} = $value;
    }
    return $self->{PermitRootLogin};
}

#@method
sub ClientAliveInterval {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{ClientAliveInterval} = $value;
    }
    return $self->{ClientAliveInterval};
}

#@method
sub ClientAliveCountMax {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{ClientAliveCountMax} = $value;
    }
    return $self->{ClientAliveCountMax};
}

#@method
sub PermitEmptyPasswords {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitEmptyPasswords} = $value;
    }
    return $self->{PermitEmptyPasswords};
}

#@method
sub PermitUserEnvironment {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{PermitUserEnvironment} = $value;
    }
    return $self->{PermitUserEnvironment};
}

#@method
sub HostbasedAuthentication {
    my ( $self, $value ) = @ARG;
    if ( @ARG == 2 ) {
        $self->{HostbasedAuthentication} = $value;
    }
    return $self->{HostbasedAuthentication};
}

1;

__END__
