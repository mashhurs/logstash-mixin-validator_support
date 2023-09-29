# encoding: utf-8

require 'logstash/plugin_mixins/validator_support/host_port_pair_validation_adapter'

describe LogStash::PluginMixins::ValidatorSupport::HostPortPairValidationAdapter do

  it 'is an instance of NamedValidationAdapter' do
    expect(described_class).to be_a_kind_of LogStash::PluginMixins::ValidatorSupport::NamedValidationAdapter
  end

  context '#validate' do
    [
      ["127.0.0.1:1234"],
      ["82.31.1.3:9800"],
      ["foo.com:1234"],
      ["foo-bar-domain.com:9800"],
      ["::1:9800"],
      ["::1"],
      ["2001:db8:3333:4444:5555:6666:7777:8888:9800"],
      ["::ffff:93.184.216.34:1023"],
      ["127.0.0.1"],
      ["::ffff:93.184.216.34"],
      ["2001:db8:3333:4444:5555:6666:7777:8888"],
      ["foo-bar-domain.com"]
    ].each do |candidate|
      context "valid input `#{candidate.inspect}`" do
        it 'correctly reports the value as valid', :aggregate_failures do
          is_valid_result, coerced_or_error = described_class.validate(candidate)

          expect(is_valid_result).to be true
          expect(coerced_or_error).to eq candidate.first
        end
      end
    end
  end
end