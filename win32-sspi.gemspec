require 'rubygems'

Gem::Specification.new do |spec|
  spec.name       = 'win32-sspi'
  spec.summary    = 'Yet another SSPI library for Windows'
  spec.version    = '0.0.1.rc2'
  spec.authors    = ['Daniel Edgar', 'Gary Sick', 'Daniel J. Berger']
  spec.license    = 'MIT'
  spec.email      = 'aknot242@gmail.com'
  spec.platform   = Gem::Platform::CURRENT
  spec.required_ruby_version = '>=1.9'
  spec.homepage   = 'https://github.com/aknot242/win32-sspi'
  spec.files      = Dir['**/*'].reject{ |f| f.include?('git') || f.include?('Notes.txt') }
  spec.test_files = Dir['test/*.rb']
  spec.require_paths = ['lib','lib/win32/sspi']
  spec.has_rdoc   = false

  spec.extra_rdoc_files  = ['README.md']

  spec.add_dependency('ffi', '~>1.9')
  spec.add_development_dependency('test-unit','~>3.0')
  spec.requirements << "This gem will only work in Windows Environment."

  spec.description = <<-EOF
    A SSPI library for Ruby on Windows using FFI under the hood.
    Supports NTLM and Negotiate protocols.
    See examples for usage.
  EOF
end
