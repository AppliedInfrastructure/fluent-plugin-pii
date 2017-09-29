# -*- encoding: utf-8 -*-
Gem::Specification.new do |gem|
  gem.name          = "fluent-plugin-pii"
  gem.version       = "1.0.1"
  gem.authors       = ["Michael Laws"]
  gem.email         = ["mlaws@appliedinfrastructure.com"]
  gem.summary       = %q{A Fluentd filter plugin to find and filter PII from syslog messages.}
  gem.description   = %q{A Fluentd filter plugin to find and filter PII from syslog messages.}
  gem.homepage      = "https://github.com/AppliedrInfrastructure/fluent-plugin-pii"
  gem.license       = "Apache-2.0"

  gem.require_paths = ["lib"]
  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})

  gem.add_runtime_dependency     "fluentd"
  gem.add_development_dependency "test-unit"
end
