# encoding: utf-8

require 'logstash/plugin_mixins/validator_support'

module LogStash
  module PluginMixins
    module ValidatorSupport

      host_port_regex = %r{(?:(?:[a-z][a-z0-9\-\.])|(([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4})|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b))(:?:[0-9]{1,5})?$}xi

      HostPortPairValidationAdapter = NamedValidationAdapter.new(:host_port_pair) do |value|
        break ValidationResult.failure("Expected exactly one host:port pair, got `#{value.inspect}`") unless value.kind_of?(Array) && value.size <= 1

        candidate = value.first

        break ValidationResult.failure("Expected a valid host:port pair, got `#{candidate.inspect}`") unless host_port_regex =~ candidate

        break ValidationResult.success(candidate)
      end
    end
  end
end