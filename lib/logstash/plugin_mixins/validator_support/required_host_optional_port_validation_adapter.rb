# encoding: utf-8

require 'logstash/plugin_mixins/validator_support'

require 'resolv'

module LogStash
  module PluginMixins
    module ValidatorSupport

      bare_hostname_pattern = %r{\A([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\Z}i

      host_port_pair = Struct.new(:host, :port)

      expectation_desc = "required-host optional-port pair"

      RequiredHostOptionalPortValidationAdapter = NamedValidationAdapter.new(:required_host_optional_port) do |value|
        break ValidationResult.failure("Expected exactly one #{expectation_desc}, got `#{value.inspect}`") unless value.kind_of?(Array) && value.size <= 1

        candidate = value.first

        break ValidationResult.failure("Expected a valid #{expectation_desc}, got `#{candidate.inspect}`") unless candidate.kind_of?(String) && !candidate.empty?

        # optional port
        candidate_host, candidate_port = candidate.split(%r{\:(?=\d{1,5}\z)},2)
        port = candidate_port&.to_i

        # bracket-wrapped ipv6
        if candidate_host.start_with?('[') && candidate_host.end_with?(']')
          candidate_host = candidate_host[1...-1]
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if Resolv::IPv6::Regex.match? candidate_host
        else
          # ipv4 or ipv6
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if Resolv::IPv4::Regex.match? candidate_host
          break ValidationResult.success(host_port_pair.new(candidate_host, port)) if bare_hostname_pattern.match? candidate_host
        end

        break ValidationResult.failure("Expected a valid #{expectation_desc}, got `#{candidate.inspect}`")
      end
    end
  end
end