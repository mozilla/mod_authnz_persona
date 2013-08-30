use Apache::TestMM qw(test clean);
use Apache::TestRun ();

Apache::TestMM::filter_args();
Apache::TestRun->generate_script();
