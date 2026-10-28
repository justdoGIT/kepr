# frozen_string_literal: true

Gem::Specification.new do |s|
  s.name = 'kepr'
  s.version = '0.1.0'
  s.summary = 'Client for the kepr credential daemon'
  s.description = 'Get, set, generate, delete and list kepr credentials over the daemon socket.'
  s.authors = ['kepr']
  s.licenses = ['MIT', 'Apache-2.0']
  s.required_ruby_version = '>= 2.7'
  s.files = Dir['lib/**/*.rb'] + ['README.md']
  s.require_paths = ['lib']
end
