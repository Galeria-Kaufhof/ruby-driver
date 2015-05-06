require 'spec_helper'

describe Cassandra do

  let(:connect_options) { {} }

  describe '.cluster' do
    let(:some_future) { double :future, get: :future_result }
    before do
      expect(described_class).to receive(:cluster_async).with(connect_options) { some_future }
    end
    subject { described_class.cluster(connect_options) }
    it { should eq(:future_result) }
  end

  describe '.cluster_async' do

    subject { described_class.cluster_async(connect_options) }

    before do
      allow_any_instance_of(Cassandra::Driver).to receive(:connect) { :future_result }
    end

    it { should eq(:future_result) }

    context 'using invalid options' do
      context 'negative idle_timeout' do
        let(:connect_options) { { idle_timeout: -1 } }
        it { should be_kind_of(Cassandra::Future::Error) }
      end
    end

  end
end
