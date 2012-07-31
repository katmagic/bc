Gem::Specification.new do |s|
  s.name        = 'bc'
  s.version     = '0.2.2'
  s.author      = 'katmagic'
  s.email       = 'the.magical.kat@gmail.com'
  s.homepage    = 'https://github.com/katmagic/bc'
  s.summary     = 'Interface with bitcoind.'
  s.description = 'bc is a Ruby interface to bitcoind.'

  s.files = ['lib/bc.rb', 'README.md', 'UNLICENSE']
  s.add_dependency('jr')

	if ENV['GEM_SIG_KEY']
		s.signing_key = ENV['GEM_SIG_KEY']
		s.cert_chain = ENV['GEM_CERT_CHAIN'].split(",") if ENV['GEM_CERT_CHAIN']
	else
		warn "environment variable $GEM_SIG_KEY unspecified; not signing gem"
	end
end
