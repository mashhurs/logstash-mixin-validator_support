Gem::Specification.new do |s|
  s.name          = 'logstash-mixin-validator_support'
  s.version       = '1.0.1'
  s.licenses      = %w(Apache-2.0)
  s.summary       = "Support for the plugin parameter validations introduced in recent releases of Logstash, for plugins wishing to use them on older Logstashes"
  s.description   = "This gem is meant to be a dependency of any Logstash plugin that wishes to use validators introduced in recent versions of Logstash while maintaining backward-compatibility with earlier Logstashes. When used on older Logstash versions, it provides back-ports of the new validators."
  s.authors       = %w(Elastic)
  s.email         = 'info@elastic.co'
  s.homepage      = 'https://github.com/logstash-plugins/logstash-mixin-validator_support'
  s.require_paths = %w(lib)

  s.files = %w(lib spec vendor).flat_map{|dir| Dir.glob("#{dir}/**/*")}+Dir.glob(["*.md","LICENSE"])

  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  s.platform = RUBY_PLATFORM

  # This support gem must have a runtime dependency on the OLDEST supported
  # MAJOR.MINOR of Logstash. This enables plugins that use adapters provided
  # by this support library to run on any supported Logstash, which in turn
  # allows us to release patch-level fixes on those plugins without maintaining
  # multiple branches.
  s.add_runtime_dependency 'logstash-core', '>= 6.8'

  s.add_development_dependency 'rspec', '~> 3.9'
  s.add_development_dependency 'logstash-devutils'
end
