# coding: utf-8
Gem::Specification.new do |s|
  s.name          = 'logstash-filter-accesswatch'
  s.version       = '0.2.0'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'The Logstash filter plugin for Access Watch (http://access.watch).'
  s.description   = 'The Access Watch filter adds information about robots visiting your website based on data from our robot database.'
  s.homepage      = 'http://access.watch'
  s.authors       = ['Benoît Fleury']
  s.email         = 'benoit@access.watch'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE']

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { 'logstash_plugin' => 'true',
                 'logstash_group' => 'filter' }

  # Gem dependencies
  s.add_runtime_dependency 'logstash-core-plugin-api',   '~> 2.0'
  s.add_runtime_dependency 'logstash-mixin-http_client', '~> 5.2'
  s.add_runtime_dependency 'lru_redux',                  '~> 1.1'

  s.add_development_dependency 'logstash-devutils', '1.3.3'
end
