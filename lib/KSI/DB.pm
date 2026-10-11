package KSI::DB;

use v5.36;
use strict;
use warnings;
use DBI;
use Carp qw(croak);

sub dsn_from_env ($class, $uri = $ENV{SQL_ALCHEMY_URI} // $ENV{DATABASE_URL}) {
    croak 'Set SQL_ALCHEMY_URI or DATABASE_URL' unless defined $uri && length $uri;
    return ("dbi:SQLite:dbname=$1", undef, undef, { sqlite_unicode => 1 })
        if $uri =~ m{\Asqlite:///(.*)\z};
    return ("dbi:SQLite:dbname=$1", undef, undef, { sqlite_unicode => 1 })
        if $uri =~ m{\Asqlite:(?!//)(.*)\z};
    return ("dbi:mysql:database=$5;host=$3" . (defined $4 ? ";port=$4" : ''), $1, $2, { mysql_enable_utf8mb4 => 1 })
        if $uri =~ m{\Amysql(?:\+pymysql)?://([^:]+):([^@]+)@([^/:]+)(?::(\d+))?/([^?]+)(?:\?[^#]*)?\z};
    croak 'Unsupported database URI';
}

sub connect ($class) {
    my ($dsn, $user, $password, $attrs) = $class->dsn_from_env;
    my $dbh = DBI->connect($dsn, $user, $password, {
        RaiseError => 1, PrintError => 0, AutoCommit => 1, %$attrs,
    }) or croak 'Database connection failed';
    if ($dsn =~ /\Adbi:mysql:/) {
        $dbh->do(q{SET sql_mode=(SELECT REPLACE(@@sql_mode,'ONLY_FULL_GROUP_BY',''))});
    }
    return $dbh;
}

1;
