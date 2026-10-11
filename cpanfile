requires 'perl', '5.036';
requires 'Mojolicious', '9.30';
requires 'DBI', '1.643';
requires 'DBD::SQLite', '1.72';
requires 'DBD::mysql', '4.050';
on 'test' => sub {
    requires 'Test::More';
};
