lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'echspec/version'

Gem::Specification.new do |spec|
  spec.name          = 'echspec'
  spec.version       = EchSpec::VERSION
  spec.authors       = ['thekuwayama']
  spec.email         = ['thekuwayama@gmail.com']
  spec.summary       = 'A conformance testing tool for ECH implementation'
  spec.description   = spec.summary
  spec.homepage      = 'https://github.com/thekuwayama/echspec'
  spec.license       = 'MIT'
  spec.required_ruby_version = '>=3.1'

  spec.files         = `git ls-files`.split($INPUT_RECORD_SEPARATOR)
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']
  spec.bindir        = 'exe'
  spec.executables   = ['echspec']

  spec.add_development_dependency 'bundler'
  spec.add_dependency             'base64'
  spec.add_dependency             'resolv', '> 0.4.0'
  spec.add_dependency             'tttls1.3', '~> 0.3.4'
end
