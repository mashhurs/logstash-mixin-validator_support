# encoding: utf-8

require 'logstash/plugin_mixins/validator_support'

module LogStash
  module PluginMixins
    module ValidatorSupport
      field_name = /[^\[\]]+/                                     # anything but brackets
      path_fragment = /\[#{field_name}\]/                         # bracket-wrapped field name
      field_reference_literal = /#{path_fragment}+/               # one or more path fragments
      embedded_field_reference = /\[#{field_reference_literal}\]/ # bracket-wrapped field reference literal
      composite_field_reference = /#{Regexp.union(path_fragment, embedded_field_reference)}+/

      # anchored pattern matching either a stand-alone field name, or a composite field reference
      field_reference_pattern = /\A#{Regexp.union(field_name,composite_field_reference)}\z/

      FieldReferenceValidationAdapter = NamedValidationAdapter.new(:field_reference) do |value|
        break ValidationResult.failure("Expected exactly one field reference, got `#{value.inspect}`") unless value.kind_of?(Array) && value.size <= 1

        candidate = value.first

        break ValidationResult.success(nil) if value.empty? || candidate.nil? || candidate.empty?

        break ValidationResult.failure("Expected a valid field reference, got `#{candidate.inspect}`") unless field_reference_pattern =~ candidate

        break ValidationResult.success(candidate)
      end
    end
  end
end
