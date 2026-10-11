use v5.36;
use strict;
use warnings;
use Test::More;
use Test::Mojo;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use DBI;
use lib 'lib';
use KSI::Auth qw(hash_password);

my $dir = tempdir(CLEANUP => 1);
my $dbfile = "$dir/test.sqlite";
$ENV{SQL_ALCHEMY_URI} = "sqlite:///$dbfile";
$ENV{MOJO_SECRET} = 'test-only-secret';
$ENV{KSI_CONTENT_ROOT} = "$dir/content";
make_path("$dir/content/articles/1");
open my $content_file, '>', "$dir/content/articles/1/example.txt" or die $!;
print {$content_file} "content\n";
close $content_file;
my $dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", '', '', {RaiseError => 1});
$dbh->do(q{CREATE TABLE users (
    id INTEGER PRIMARY KEY, email VARCHAR(50) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, role TEXT NOT NULL DEFAULT 'participant',
    last_logged_in TEXT
)});
$dbh->do(q{CREATE TABLE oauth2_tokens (
    access_token VARCHAR(150) PRIMARY KEY, user INTEGER, expire TEXT,
    refresh_token VARCHAR(150), granted TEXT
)});
$dbh->do(q{CREATE TABLE years (
    id INTEGER PRIMARY KEY, year TEXT, sealed INTEGER NOT NULL, point_pad REAL NOT NULL
)});
$dbh->do(q{CREATE TABLE waves (
    id INTEGER PRIMARY KEY, year INTEGER NOT NULL, `index` INTEGER NOT NULL,
    caption TEXT, garant INTEGER NOT NULL, time_published TEXT NOT NULL
)});
$dbh->do(q{CREATE TABLE tasks (
    id INTEGER PRIMARY KEY, wave INTEGER NOT NULL, thread INTEGER
)});
$dbh->do(q{CREATE TABLE modules (
    id INTEGER PRIMARY KEY, task INTEGER NOT NULL, max_points REAL, bonus INTEGER NOT NULL DEFAULT 0
)});
$dbh->do(q{CREATE TABLE active_orgs (org INTEGER NOT NULL, year INTEGER NOT NULL, PRIMARY KEY (org, year))});
$dbh->do(q{CREATE TABLE achievements (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, picture TEXT NOT NULL,
    description TEXT, year INTEGER
)});
$dbh->do(q{CREATE TABLE config (key TEXT PRIMARY KEY, value TEXT, secret INTEGER NOT NULL DEFAULT 0)});
$dbh->do(q{CREATE TABLE articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT, author INTEGER NOT NULL, title TEXT NOT NULL,
    body TEXT, picture TEXT, time_created TEXT NOT NULL, published INTEGER,
    year INTEGER NOT NULL, resource TEXT
)});
$dbh->do(q{CREATE TABLE threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, public INTEGER NOT NULL DEFAULT 1, year INTEGER NOT NULL
)});
$dbh->do(q{CREATE TABLE posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, thread INTEGER NOT NULL, author INTEGER NOT NULL,
    body TEXT NOT NULL, published_at TEXT NOT NULL, parent INTEGER
)});
$dbh->do(q{CREATE TABLE threads_visits (
    thread INTEGER NOT NULL, user INTEGER NOT NULL, last_visit TEXT NOT NULL,
    last_last_visit TEXT, PRIMARY KEY (thread, user)
)});
$dbh->do(q{CREATE TABLE solution_comments (thread INTEGER NOT NULL, user INTEGER NOT NULL, task INTEGER NOT NULL, PRIMARY KEY (thread, user, task))});
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 7, 'person@example.test', hash_password('good-password'), 1);
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 8, 'disabled@example.test', hash_password('good-password'), 0);
$dbh->do('INSERT INTO users (id, email, password, enabled, role) VALUES (?, ?, ?, ?, ?)',
    undef, 9, 'admin@example.test', hash_password('good-password'), 1, 'admin');
$dbh->do('INSERT INTO users (id, email, password, enabled) VALUES (?, ?, ?, ?)',
    undef, 10, 'other@example.test', hash_password('good-password'), 1);
$dbh->do('INSERT INTO years VALUES (2025, ?, 0, 1.5)', undef, '2025/2026');
$dbh->do('INSERT INTO waves VALUES (10, 2025, 1, "Wave one", 9, "2020-01-01 00:00:00")');
$dbh->do('INSERT INTO waves VALUES (11, 2025, 2, "Wave two", 9, "2099-01-01 00:00:00")');
$dbh->do('INSERT INTO tasks (id, wave, thread) VALUES (100, 10, 22)');
$dbh->do('INSERT INTO tasks (id, wave, thread) VALUES (101, 10, 22)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1000, 100, 5, 0)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1001, 100, 3, 0)');
$dbh->do('INSERT INTO modules (id, task, max_points, bonus) VALUES (1002, 100, 2, 1)');
$dbh->do('INSERT INTO articles (author, title, body, time_created, published, year, resource) VALUES (9, ?, ?, ?, 1, 2025, ?)',
    undef, 'Published article', 'Public body', '2020-01-01 12:00:00', 'articles/1');
$dbh->do('INSERT INTO articles (author, title, body, time_created, published, year) VALUES (9, ?, ?, ?, 0, 2025)',
    undef, 'Draft article', 'Private body', '2021-01-01 12:00:00');
$dbh->do('UPDATE articles SET resource = ? WHERE title = ?', undef, '../../outside', 'Draft article');
$dbh->do('INSERT INTO threads (id, title, public, year) VALUES (20, ?, 1, 2025)', undef, 'Public thread');
$dbh->do('INSERT INTO threads (id, title, public, year) VALUES (21, ?, 0, 2025)', undef, 'Private thread');
$dbh->do('INSERT INTO threads (id, title, public, year) VALUES (22, ?, 1, 2025)', undef, 'Task thread');
$dbh->do('INSERT INTO posts (id, thread, author, body, published_at, parent) VALUES (1, 20, 7, ?, ?, NULL)', undef, 'Root post', '2020-01-01 00:00:00');
$dbh->do('INSERT INTO posts (id, thread, author, body, published_at, parent) VALUES (2, 20, 7, ?, ?, 1)', undef, 'Reaction', '2020-01-02 00:00:00');
$dbh->do('INSERT INTO posts (id, thread, author, body, published_at, parent) VALUES (3, 21, 7, ?, ?, NULL)', undef, 'Private post', '2020-01-03 00:00:00');
$dbh->disconnect;

my $t = Test::Mojo->new('KSI::App');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'good-password'})
  ->status_is(200)->json_has('/access_token')->json_is('/token_type' => 'Bearer')->json_is('/expires_in' => 3600);
my $first = $t->tx->res->json;
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'bad'})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->post_ok('/auth' => form => {grant_type => 'password', username => q{' OR 1=1 --}, password => 'good-password'})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'disabled@example.test', password => 'good-password'})
  ->status_is(400)->json_is('/error' => 'account_disabled');
$t->get_ok('/logout' => {Authorization => "Bearer $first->{access_token}"})->status_is(204);
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $first->{refresh_token}})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'person@example.test', password => 'good-password'})
  ->status_is(200);
my $second = $t->tx->res->json;
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $second->{refresh_token}})
  ->status_is(200)->json_has('/access_token')->json_is('/token_type' => 'Bearer');
my $rotated = $t->tx->res->json;
$t->post_ok('/auth' => form => {grant_type => 'refresh_token', refresh_token => $second->{refresh_token}})
  ->status_is(400)->json_is('/error' => 'unauthorized_client');
$t->get_ok('/years')->status_is(200)->json_is('/years/0/sum_points' => 8)
  ->json_is('/years/0/tasks_cnt' => 2)->json_is('/years/0/index' => 2025);
$t->get_ok('/years/2025')->status_is(200)->json_is('/year/sum_points' => 8);
$t->get_ok('/years/9999')->status_is(404);
$t->head_ok('/years')->status_is(200)->content_is('');
$t->get_ok('/waves')->status_is(200)->json_is('/waves/0/sum_points' => 8)
  ->json_is('/waves/0/tasks_cnt' => 2)->json_is('/waves/0/public' => 1);
$t->get_ok('/waves/11')->status_is(200)->json_is('/wave/public' => 0);
$t->post_ok('/years' => json => {year => {index => 2026, year => '2026/2027', sealed => 0, point_pad => 0, active_orgs => [7]}})
  ->status_is(400);
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'admin@example.test', password => 'good-password'})
  ->status_is(200);
my $admin = $t->tx->res->json;
$t->get_ok('/waves' => {Authorization => "Bearer $admin->{access_token}"})
  ->status_is(200)->json_is('/waves/1/id' => 11);
$t->put_ok('/waves/11' => {Authorization => "Bearer $admin->{access_token}"} => json => {wave => {index => 3, caption => 'Updated', garant => 9}})
  ->status_is(200)->json_is('/wave/index' => 3)->json_is('/wave/caption' => 'Updated');
$t->post_ok('/waves' => {Authorization => "Bearer $admin->{access_token}"} => json => {wave => {index => 4, caption => 'New', garant => 9, time_published => '2099-01-01 00:00:00'}})
  ->status_is(200)->json_is('/wave/index' => 4);
$t->delete_ok('/waves/10' => {Authorization => "Bearer $admin->{access_token}"})->status_is(403);
$t->delete_ok('/waves/11' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)->json_is({});
$t->post_ok('/years' => {Authorization => "Bearer $admin->{access_token}"} => json => {year => {index => 2026, year => '2026/2027', sealed => 0, point_pad => 0, active_orgs => [7]}})
  ->status_is(200)->json_is('/year/index' => 2026)->json_is('/year/sum_points' => 0);
$t->get_ok('/years/2026')->status_is(200)->json_is('/year/tasks_cnt' => 0);
$t->put_ok('/years/2026' => {Authorization => "Bearer $admin->{access_token}"} => json => {year => {index => 2027, year => '2027/2028', sealed => 1, point_pad => 2.5, active_orgs => [9]}})
  ->status_is(200)->json_is('/year/index' => 2027)->json_is('/year/sealed' => 1);
$t->get_ok('/years/2027')->status_is(200)->json_is('/year/point_pad' => 2.5);
$t->delete_ok('/years/2025' => {Authorization => "Bearer $admin->{access_token}"})->status_is(403);
$t->delete_ok('/years/2027' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)->json_is({});
$t->post_ok('/achievements' => {Authorization => "Bearer $admin->{access_token}"} => json => {achievement => {title => 'Prize', picture => 'prize.svg', description => 'Test', persistent => 0}})
  ->status_is(200)->json_is('/achievement/title' => 'Prize')->json_is('/achievement/year' => 2025);
my $achievement = $t->tx->res->json->{achievement};
$dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", '', '', {RaiseError => 1});
$dbh->do('INSERT INTO config (key, value) VALUES (?, ?)', undef, 'successful_participant_trophy_id', $achievement->{id});
$dbh->disconnect;
$t->get_ok('/achievements/special/successful')->status_is(200)->json_is('/achievement/id' => $achievement->{id});
$t->put_ok('/achievements/' . $achievement->{id} => {Authorization => "Bearer $admin->{access_token}"} => json => {achievement => {title => 'Persistent Prize', picture => 'prize.svg', description => 'Test', persistent => 1}})
  ->status_is(200)->json_is('/achievement/persistent' => 1)->json_is('/achievement/year' => undef);
$t->get_ok('/achievements')->status_is(200)->json_is('/achievements/0/title' => 'Persistent Prize');
$t->delete_ok('/achievements/' . $achievement->{id} => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)->json_is({});
$t->get_ok('/articles')->status_is(200)->json_is('/meta/total' => 1)
  ->json_is('/articles/0/title' => 'Published article')->json_is('/articles/0/picture' => 'img/box-ksi.svg');
$t->get_ok('/articles/2')->status_is(400);
$t->get_ok('/articles/999')->status_is(404)->json_is('/errors/0/status' => '404');
$t->post_ok('/articles' => json => {article => {title => 'No access'}})
  ->status_is(400)->json_is('/errors/0/title' => 'Unauthorized');
$t->get_ok('/articles' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)
  ->json_is('/meta/total' => 2)->json_is('/contents/0/files' => [])
  ->json_is('/contents/1/id' => 'articles/1')->json_is('/contents/1/files/0' => 'example.txt');
$t->get_ok('/articles?_start=0&_limit=1' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)
  ->json_is('/meta/total' => 2)->json_is('/articles/0/title' => 'Draft article');
$t->post_ok('/articles' => {Authorization => "Bearer $admin->{access_token}"} => json => {article => {title => 'New article', body => 'New body', published => 1, time_published => '2025-02-03T04:05:06Z', picture => 'new.svg'}})
  ->status_is(200)->json_is('/article/title' => 'New article')->json_is('/article/content' => 'articles/3');
$t->put_ok('/articles/3' => {Authorization => "Bearer $admin->{access_token}"} => json => {article => {title => 'Changed article', body => 'Changed body', published => 1, time_published => '2025-02-04T04:05:06Z', picture => 'new.svg'}})
  ->status_is(200)->json_is('/article/title' => 'Changed article')->json_is('/article/time_published' => '2025-02-04T04:05:06');
$t->delete_ok('/articles/3' => {Authorization => "Bearer $admin->{access_token}"})->status_is(200)->json_is({});
$t->get_ok('/threads')->status_is(200)->json_is('/threads/0/id' => 20);
$t->get_ok('/threads?wave=10')->status_is(200)->json_is('/threads/0/id' => 22);
$t->get_ok('/threads/20')->status_is(200)->json_is('/thread/posts_count' => 2)->json_is('/thread/unread' => 2);
$t->get_ok('/threads/21')->status_is(400);
$t->put_ok('/threads/20' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200)->json_is({});
$t->get_ok('/threads/20' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200)->json_is('/thread/unread' => 0);
$t->get_ok('/threadDetails/20' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200)
  ->json_is('/threadDetails/root_posts' => [1])->json_is('/posts/0/reaction' => [2])->json_is('/posts/0/is_new' => 1);
$t->put_ok('/threads/20' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200);
$t->get_ok('/threadDetails/20' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200)->json_is('/posts/0/is_new' => 0);
$dbh = DBI->connect("dbi:SQLite:dbname=$dbfile", '', '', {RaiseError => 1});
$dbh->do('INSERT INTO solution_comments (thread, user, task) VALUES (21, 7, 100)');
$dbh->disconnect;
$t->get_ok('/threads/21' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200);
$t->post_ok('/threads' => {Authorization => "Bearer $rotated->{access_token}"} => json => {thread => {title => 'Discussion'}})
  ->status_is(200)->json_is('/thread/title' => 'Discussion');
$t->post_ok('/threads' => {Authorization => "Bearer $rotated->{access_token}"} => json => {thread => {title => 'x' x 101}})
  ->status_is(413);
$t->get_ok('/posts/1')->status_is(200)->json_is('/post/reaction' => [2])->json_is('/post/is_new' => 0);
$t->get_ok('/posts/3')->status_is(400);
$t->put_ok('/posts/1' => {Authorization => "Bearer $rotated->{access_token}"} => json => {post => {body => 'Edited root'}})
  ->status_is(200)->json_is('/post/body' => 'Edited root');
$t->put_ok('/posts/1' => {Authorization => "Bearer $rotated->{access_token}"} => json => {post => {body => 'x' x 8001}})
  ->status_is(413);
$t->delete_ok('/posts/2' => {Authorization => "Bearer $rotated->{access_token}"})->status_is(200)->json_is({});
$t->post_ok('/auth' => form => {grant_type => 'password', username => 'other@example.test', password => 'good-password'})
  ->status_is(200);
my $other = $t->tx->res->json;
$t->delete_ok('/posts/1' => {Authorization => "Bearer $other->{access_token}"})->status_is(403);
$t->put_ok('/posts/1' => {Authorization => "Bearer $other->{access_token}"} => json => {post => {body => 'Not mine'}})
  ->status_is(200)->json_is('/post/body' => 'Edited root');
done_testing;
