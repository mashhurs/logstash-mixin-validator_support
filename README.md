# Validator Support Mixin

This gem provides back-ports of new validators that have been added to Logstash
core. By using this support adapter, plugin developers can use newly-introduced
validators without constraining the versions of Logstash on which their plugin
can run.

When a plugin using this adapter runs on a version of Logstash that does _not_
provide the named validator, the back-ported validator provided by this adapter
is used instead.

## Usage

1. Add this gem as a runtime dependency of your plugin. To avoid conflicts with
   other plugins, you should always use the [pessimistic operator][] `~>` to
   match the minimum `1.x` that provides the back-ports you intend to use:

    ~~~ ruby
    Gem::Specification.new do |s|
      # ...

      s.add_runtime_dependency 'logstash-mixin-validator_support', '~>1.0'
    end
    ~~~

2. In your plugin code, require this library and extend one or more of the
   provided validators into your plugin. For example, to use the
   `:field_reference` validator introduced in Logstash 7.11:

    ~~~ ruby
    require 'logstash/plugin_mixins/validator_support/field_reference_validation_adapter'

    class LogStash::Inputs::Foo < Logstash::Inputs::Base
      extend LogStash::PluginMixins::ValidatorSupport::FieldReferenceValidationAdapter

      # ...
    end
    ~~~

3. Use the validator as normal when defining config options; your plugin does
   not need to know whether the validator was provided by Logstash core or by
   this gem.

    ~~~ ruby
      config :target, :validate => :field_reference
    ~~~

## Development

This gem:
 - *MUST* remain API-stable at 1.x
 - *MUST NOT* introduce additional runtime dependencies

When developing back-ports, sometimes it may not be possible to provide a
verbatim validation. In these cases, developers should err on the side of the
back-port accepting input that the core implementation may consider invalid.

Each time a new validator is added, the runtime dependency of this library on
Logstash core should be updated to require a minimium of the OLDEST supported
release. This allows plugins using this adapter to supply patch-level fixes to
any supported Logstash version without maintaining multiple branches.

[pessimistic operator]: https://thoughtbot.com/blog/rubys-pessimistic-operator
