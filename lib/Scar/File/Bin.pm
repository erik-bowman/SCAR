package Scar::File::Bin;

# Standard Pragmas
use utf8;
use strict;
use warnings FATAL => 'all';

# Standard Modules
use Carp qw{ croak };
use English qw{ -no_matched_vars };

# Local Modules
use Scar::File;
use Scar::Commands;
use Scar::Util::Log;

#@method
#@returns Scar::File::Bin
sub new {
    my ($class) = @ARG;
    my $self = bless {}, $class;

    log_info('Building system bianry datastore');

    my @bin_dirs
        = qw{ /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin };

    foreach my $bin_dir (@bin_dirs) {

        log_info("Checking $bin_dir...");

        my @dir_contents = run_find("-L $bin_dir -type f");

        foreach my $content (@dir_contents) {
            chomp $content;
            $self->{$content}->{permissions}
                = get_file_permissions($content);
            $self->{$content}->{owner}
                = get_file_owner($content);
            $self->{$content}->{group}
                = get_file_group($content);
            log_debug("Added $content");
        }
    }

    log_info('Done building system binary datastore');
    return $self;
}

1;

__END__
