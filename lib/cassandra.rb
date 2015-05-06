# encoding: utf-8

#--
# Copyright 2013-2015 DataStax, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#++


require 'ione'
require 'json'

require 'monitor'
require 'ipaddr'
require 'set'
require 'bigdecimal'
require 'forwardable'
require 'digest'
require 'stringio'
require 'resolv'
require 'openssl'
require 'securerandom'
require 'time'

module Cassandra
  # A list of all supported request consistencies
  # @see http://www.datastax.com/documentation/cassandra/2.0/cassandra/dml/dml_config_consistency_c.html Consistency levels in Apache Cassandra 2.0
  # @see http://www.datastax.com/documentation/cassandra/1.2/cassandra/dml/dml_config_consistency_c.html Consistency levels in Apache Cassandra 1.2
  # @see Cassandra::Session#execute_async
  CONSISTENCIES = [ :any, :one, :two, :three, :quorum, :all, :local_quorum,
                    :each_quorum, :serial, :local_serial, :local_one ].freeze

  # A list of all supported serial consistencies
  # @see Cassandra::Session#execute_async
  SERIAL_CONSISTENCIES = [:serial, :local_serial].freeze

  # A list of all possible write types that a
  # {Cassandra::Errors::WriteTimeoutError} can have.
  #
  # @see https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v1.spec#L591-L603 Description of possible types of writes in Apache Cassandra native protocol spec v1
  WRITE_TYPES = [:simple, :batch, :unlogged_batch, :counter, :batch_log].freeze

  # Creates a {Cassandra::Cluster Cluster instance}.
  #
  # @option options [Array<String, IPAddr>] :hosts (['127.0.0.1']) a list of
  #   initial addresses. Note that the entire list of cluster members will be
  #   discovered automatically once a connection to any hosts from the original
  #   list is successful.
  #
  # @option options [Integer] :port (9042) cassandra native protocol port.
  #
  # @option options [String] :datacenter (nil) name of current datacenter.
  #   First datacenter found will be assumed current by default. Note that you
  #   can skip this option if you specify only hosts from the local datacenter
  #   in `:hosts` option.
  #
  # @option options [Boolean] :shuffle_replicas (true) whether replicas list
  #   found by the default Token-Aware Load Balancing Policy should be
  #   shuffled. See {Cassandra::LoadBalancing::Policies::TokenAware#initialize Token-Aware Load Balancing Policy}.
  #
  # @option options [Numeric] :connect_timeout (10) connection timeout in
  #   seconds. Setting value to `nil` will reset it to 5 seconds.
  #
  # @option options [Numeric] :timeout (10) request execution timeout in
  #   seconds. Setting value to `nil` will remove request timeout.
  #
  # @option options [Numeric] :heartbeat_interval (30) how often should a
  #   heartbeat be sent to determine if a connection is alive. Several things to
  #   note about this option. Only one heartbeat request will ever be
  #   outstanding on a given connection. Each heatbeat will be sent in at least
  #   `:heartbeat_interval` seconds after the last request has been sent on a
  #   given connection. Setting value to `nil` will remove connection timeout.
  #
  # @option options [Numeric] :idle_timeout (60) period of inactivity after
  #   which a connection is considered dead. Note that this value should be at
  #   least a few times larger than `:heartbeat_interval`. Setting value to
  #   `nil` will remove automatic connection termination.
  #
  # @option options [String] :username (none) username to use for
  #   authentication to cassandra. Note that you must also specify `:password`.
  #
  # @option options [String] :password (none) password to use for
  #   authentication to cassandra. Note that you must also specify `:username`.
  #
  # @option options [Boolean, OpenSSL::SSL::SSLContext] :ssl (false) enable
  #   default ssl authentication if `true` (not recommended). Also accepts an
  #   initialized {OpenSSL::SSL::SSLContext}. Note that this option should be
  #   ignored if `:server_cert`, `:client_cert`, `:private_key` or
  #   `:passphrase` are given.
  #
  # @option options [String] :server_cert (none) path to server certificate or
  #   certificate authority file.
  #
  # @option options [String] :client_cert (none) path to client certificate
  #   file. Note that this option is only required when encryption is
  #   configured to require client authentication.
  #
  # @option options [String] :private_key (none) path to client private key.
  #   Note that this option is only required when encryption is configured to
  #   require client authentication.
  #
  # @option options [String] :passphrase (none) passphrase for private key.
  #
  # @option options [Symbol] :compression (none) compression to use. Must be
  #   either `:snappy` or `:lz4`. Also note, that in order for compression to
  #   work, you must install 'snappy' or 'lz4-ruby' gems.
  #
  # @option options [Cassandra::LoadBalancing::Policy] :load_balancing_policy
  #   default: token aware data center aware round robin.
  #
  # @option options [Symbol] :address_resolution (:none) a pre-configured
  #   address resolver to use. Must be one of `:none` or
  #   `:ec2_multi_region`.
  #
  # @option options [Boolean] :synchronize_schema (true) whether the driver
  #   should automatically keep schema metadata synchronized. When enabled, the
  #   driver updates schema metadata after receiving schema change
  #   notifications from Cassandra. Setting this setting to `false` disables
  #   automatic schema updates. Schema metadata is used by the driver to
  #   determine cluster partitioners as well as to find partition keys and
  #   replicas of prepared statements, this information makes token aware load
  #   balancing possible. One can still {Cassandra::Cluster#refresh_schema refresh schema manually}.
  #
  # @option options [Numeric] :schema_refresh_delay (1) the driver will wait
  #   for `:schema_refresh_delay` before fetching metadata after receiving a
  #   schema change event. This timer is restarted every time a new schema
  #   change event is received. Finally, when the timer expires or a maximum
  #   wait time of `:schema_refresh_timeout` has been reached, a schema refresh
  #   attempt will be made and the timeout is reset.
  #
  # @option options [Numeric] :schema_refresh_timeout (10) the maximum delay
  #   before automatically refreshing schema. Such delay can occur whenever
  #   multiple schema change events are continuously arriving within
  #   `:schema_refresh_delay` interval.
  #
  # @option options [Cassandra::Reconnection::Policy] :reconnection_policy
  #   default: {Cassandra::Reconnection::Policies::Exponential Exponential}.
  #   Note that the default policy is configured with `(0.5, 30, 2)`.
  #
  # @option options [Cassandra::Retry::Policy] :retry_policy default:
  #   {Cassandra::Retry::Policies::Default Default Retry Policy}.
  #
  # @option options [Logger] :logger (none) logger. a {Logger} instance from the
  #   standard library or any object responding to standard log methods
  #   (`#debug`, `#info`, `#warn`, `#error` and `#fatal`).
  #
  # @option options [Enumerable<Cassandra::Listener>] :listeners (none)
  #   initial listeners. A list of initial cluster state listeners. Note that a
  #   `:load_balancing` policy is automatically registered with the cluster.
  #
  # @option options [Symbol] :consistency (:one) default consistency to use for
  #   all requests. Must be one of {Cassandra::CONSISTENCIES}.
  #
  # @option options [Boolean] :trace (false) whether or not to trace all
  #   requests by default.
  #
  # @option options [Integer] :page_size (10000) default page size for all
  #   select queries. Set this value to `nil` to disable paging.
  #
  # @option options [Hash{String => String}] :credentials (none) a hash of credentials - to be used with [credentials authentication in cassandra 1.2](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v1.spec#L238-L250). Note that if you specified `:username` and `:password` options, those credentials are configured automatically.
  #
  # @option options [Cassandra::Auth::Provider] :auth_provider (none) a custom auth provider to be used with [SASL authentication in cassandra 2.0](https://github.com/apache/cassandra/blob/trunk/doc/native_protocol_v2.spec#L257-L273). Note that if you have specified `:username` and `:password`, then a {Cassandra::Auth::Providers::Password Password Provider} will be used automatically.
  #
  # @option options [Cassandra::Compression::Compressor] :compressor (none) a
  #   custom compressor. Note that if you have specified `:compression`, an
  #   appropriate compressor will be provided automatically.
  #
  # @option options [Cassandra::AddressResolution::Policy]
  #   :address_resolution_policy default:
  #   {Cassandra::AddressResolution::Policies::None No Resolution Policy} a custom address resolution
  #   policy. Note that if you have specified `:address_resolution`, an
  #   appropriate address resolution policy will be provided automatically.
  #
  # @option options [Object<#all, #error, #value, #promise>] :futures_factory
  #   default: {Cassandra::Future} a futures factory to assist with integration
  #   into existing futures library. Note that promises returned by this object
  #   must conform to {Cassandra::Promise} api, which is not yet public. Things
  #   may change, use at your own risk.
  #
  # @example Connecting to localhost
  #   cluster = Cassandra.cluster
  #
  # @example Configuring {Cassandra::Cluster}
  #   cluster = Cassandra.cluster(
  #               username: username,
  #               password: password,
  #               hosts: ['10.0.1.1', '10.0.1.2', '10.0.1.3']
  #             )
  #
  # @return [Cassandra::Cluster] a cluster instance
  def self.cluster(options = {})
    cluster_async(options).get
  end

  # Creates a {Cassandra::Cluster Cluster instance}.
  #
  # @see Cassandra.cluster
  #
  # @return [Cassandra::Future<Cassandra::Cluster>] a future resolving to the
  #   cluster instance.
  def self.cluster_async(options = {})
    begin
      options, hosts = OptionsParser.new(options).for_driver
      Driver.new(options).connect(hosts)
    rescue => e
      futures = options.fetch(:futures_factory) { Driver.new.futures_factory }
      futures.error(e)
    end
  end

  # @private
  EMPTY_LIST = [].freeze
end

%w(
  uuid time_uuid tuple udt types errors compression protocol auth null_logger
  executors future cluster driver host session result statement statements
  column table keyspace execution/info execution/options execution/trace
  load_balancing reconnection retry address_resolution options_parser util
).each do |file|
  require "cassandra/#{file}"
end

# murmur3 hash extension
require 'cassandra_murmur3'

module Cassandra
  # @private
  VOID_STATEMENT = Statements::Void.new
  # @private
  VOID_OPTIONS   = Execution::Options.new({:consistency => :one})
  # @private
  NO_HOSTS       = Errors::NoHostsAvailable.new
end
