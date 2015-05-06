module Cassandra
  class OptionsParser

    # A whitelist for Cassandra::Cluster option keys
    VALID_OPTION_KEYS = [
      :credentials, :auth_provider, :compression, :hosts, :logger, :port,
      :load_balancing_policy, :reconnection_policy, :retry_policy, :listeners,
      :consistency, :trace, :page_size, :compressor, :username, :password,
      :ssl, :server_cert, :client_cert, :private_key, :passphrase,
      :connect_timeout, :futures_factory, :datacenter, :address_resolution,
      :address_resolution_policy, :idle_timeout, :heartbeat_interval, :timeout,
      :synchronize_schema, :schema_refresh_delay, :schema_refresh_timeout,
      :shuffle_replicas
    ]

    attr_accessor :options

    def self.for_driver(options={})
      OptionsParser.new(options)
    end

    def initialize(options={})
      @options = options
      for_driver!
    end

    private

    # @return [Array<Hash, Array<Cassandra::Host>>]
    def for_driver!
      # symbolize the keys and filter according to the attribute whitelist
      options = Hash[@options.map{ |k, v| [k.to_sym, v] }].select { |k, _| VALID_OPTION_KEYS.include?(k) }

      options.merge! parse_username_password

      verify_credentials
      verify_auth_provider

      options.merge! parse_certs
      verify_ssl

      options.merge! parse_compression
      verify_compressor
      verify_logger

      options.merge! parse_port
      options.merge! parse_datacenter

      verify_timeouts
      verify_load_balancing_policy
      verify_reconnection_policy
      verify_retry_policy

      options.merge! parse_listeners

      verify_consistency

      options.merge! parse_trace
      options.merge! parse_shuffle_replicas
      options.merge! parse_page_size

      verify_futures_factory

      options.merge! parse_address_resolution_policy
      verify_address_resolution_policy

      options.merge! parse_synchronize_schema

      [options, gather_hosts]
    end

    def parse_username_password
      username = options.delete(:username)
      password = options.delete(:password)

      return {} unless username || password

      if username && !password
        raise ::ArgumentError, "both :username and :password options must be specified, but only :username given"
      elsif !username && password
        raise ::ArgumentError, "both :username and :password options must be specified, but only :password given"
      end

      Util.assert_instance_of(::String, username) { ":username must be a String, #{username.inspect} given" }
      Util.assert_instance_of(::String, password) { ":password must be a String, #{password.inspect} given" }
      Util.assert_not_empty(username) { ":username cannot be empty" }
      Util.assert_not_empty(password) { ":password cannot be empty" }

      {
        credentials: {:username => username, :password => password},
        auth_provider: Auth::Providers::Password.new(username, password)
      }
    end

    def verify_credentials
      return unless options.has_key?(:credentials)
      credentials = options[:credentials]
      Util.assert_instance_of(::Hash, credentials) { ":credentials must be a hash, #{credentials.inspect} given" }
    end

    def verify_auth_provider
      return unless options.has_key?(:auth_provider)
      auth_provider = options[:auth_provider]
      Util.assert_responds_to(:create_authenticator, auth_provider) { ":auth_provider #{auth_provider.inspect} must respond to :create_authenticator, but doesn't" }
    end

    def parse_certs
      client_cert = options[:client_cert]
      private_key = options[:private_key]
      return {} unless client_cert && private_key

      if client_cert && !private_key
        raise ::ArgumentError, "both :client_cert and :private_key options must be specified, but only :client_cert given"
      elsif !client_cert && private_key
        raise ::ArgumentError, "both :client_cert and :private_key options must be specified, but only :private_key given"
      end

      client_cert = ::File.expand_path(client_cert)
      private_key = ::File.expand_path(private_key)

      Util.assert_file_exists(client_cert) { ":client_cert #{client_cert.inspect} doesn't exist" }
      Util.assert_file_exists(private_key) { ":private_key #{private_key.inspect} doesn't exist" }

      if server_cert = options[:server_cert]
        server_cert = ::File.expand_path(options[:server_cert])
        Util.assert_file_exists(server_cert) { ":server_cert #{server_cert.inspect} doesn't exist" }
      end

      return {} unless client_cert || server_cert

      context = ::OpenSSL::SSL::SSLContext.new

      if server_cert
        context.ca_file     = server_cert
        context.verify_mode = ::OpenSSL::SSL::VERIFY_PEER
      end

      if client_cert
        context.cert = ::OpenSSL::X509::Certificate.new(File.read(client_cert))

        if options.has_key?(:passphrase)
          context.key = ::OpenSSL::PKey::RSA.new(File.read(private_key), options[:passphrase])
        else
          context.key = ::OpenSSL::PKey::RSA.new(File.read(private_key))
        end
      end

      {ssl: context}
    end

    def verify_ssl
      return unless options.has_key?(:ssl)
      ssl = options[:ssl]
      Util.assert_instance_of_one_of([::TrueClass, ::FalseClass, ::OpenSSL::SSL::SSLContext], ssl) { ":ssl must be a boolean or an OpenSSL::SSL::SSLContext, #{ssl.inspect} given" }
    end

    def parse_compression
      return {} unless compression = options.delete(:compression)

      case compression
      when :snappy
        require 'cassandra/compression/compressors/snappy'
        {compressor: Compression::Compressors::Snappy.new}
      when :lz4
        require 'cassandra/compression/compressors/lz4'
        {compressor: Compression::Compressors::Lz4.new}
      else
        raise ::ArgumentError, ":compression must be either :snappy or :lz4, #{compression.inspect} given"
      end
    end

    def verify_compressor
      return unless options.has_key?(:compressor)
      compressor = options[:compressor]
      methods    = [:algorithm, :compress?, :compress, :decompress]
      Util.assert_responds_to_all(methods, compressor) { ":compressor #{compressor.inspect} must respond to #{methods.inspect}, but doesn't" }
    end

    def verify_logger
      return unless options.has_key?(:logger)
      logger  = options[:logger]
      methods = [:debug, :info, :warn, :error, :fatal]
      Util.assert_responds_to_all(methods, logger) { ":logger #{logger.inspect} must respond to #{methods.inspect}, but doesn't" }
    end

    def parse_port
      return {} unless port = options[:port]
      port = Integer(port)
      Util.assert_one_of(0..65536, port) { ":port must be a valid ip port, #{port} given" }
      {port: port}
    end

    def parse_datacenter
      return {} unless options.has_key?(:datacenter)
      {datacenter: options[:datacenter].to_s}
    end

    def verify_timeouts
      [ :connect_timeout, :timeout, :heartbeat_interval, :idle_timeout,
        :schema_refresh_delay, :schema_refresh_timeout
      ].each do |key|
        Util.assert_nil_or_numeric_greater_zero(options[key], key)
      end
    end

    def verify_load_balancing_policy
      return unless options.has_key?(:load_balancing_policy)
      load_balancing_policy = options[:load_balancing_policy]
      methods = [:host_up, :host_down, :host_found, :host_lost, :setup, :teardown, :distance, :plan]
      Util.assert_responds_to_all(methods, load_balancing_policy) { ":load_balancing_policy #{load_balancing_policy.inspect} must respond to #{methods.inspect}, but doesn't" }
    end

    def verify_reconnection_policy
      return unless options.has_key?(:reconnection_policy)
      reconnection_policy = options[:reconnection_policy]
      Util.assert_responds_to(:schedule, reconnection_policy) { ":reconnection_policy #{reconnection_policy.inspect} must respond to :schedule, but doesn't" }
    end

    def verify_retry_policy
      return unless options.has_key?(:retry_policy)
      retry_policy = options[:retry_policy]
      methods = [:read_timeout, :write_timeout, :unavailable]
      Util.assert_responds_to_all(methods, retry_policy) { ":retry_policy #{retry_policy.inspect} must respond to #{methods.inspect}, but doesn't" }
    end

    def parse_listeners
      return {} unless options.has_key?(:listeners)
      {listeners: Array(options[:listeners])}
    end

    def parse_trace
      return {} unless options.has_key?(:trace)
      {trace: !!options[:trace]}
    end

    def verify_consistency
      return unless options.has_key?(:consistency)
      consistency = options[:consistency]
      Util.assert_one_of(CONSISTENCIES, consistency) { ":consistency must be one of #{CONSISTENCIES.inspect}, #{consistency.inspect} given" }
    end

    def parse_shuffle_replicas
      return {} unless options.has_key?(:shuffle_replicas)
      {shuffle_replicas: !!options[:shuffle_replicas]}
    end

    def parse_page_size
      return {} unless options[:page_size]
      page_size = options[:page_size]

      page_size = Integer(page_size)
      Util.assert(page_size > 0) { ":page_size must be a positive integer, #{page_size.inspect} given" }
      {page_size: page_size}
    end

    def verify_futures_factory
      return unless options.has_key?(:futures_factory)
      futures_factory = options[:futures_factory]
      methods = [:error, :value, :promise, :all]
      Util.assert_responds_to_all(methods, futures_factory) { ":futures_factory #{futures_factory.inspect} must respond to #{methods.inspect}, but doesn't" }
    end

    def parse_address_resolution_policy
      return {} unless options.has_key?(:address_resolution)
      address_resolution = options.delete(:address_resolution)

      case address_resolution
      when :none
        {}
      when :ec2_multi_region
        {address_resolution_policy: AddressResolution::Policies::EC2MultiRegion.new}
      else
        raise ::ArgumentError, ":address_resolution must be either :none or :ec2_multi_region, #{address_resolution.inspect} given"
      end
    end

    def verify_address_resolution_policy
      return unless options.has_key?(:address_resolution_policy)
      address_resolver = options[:address_resolution_policy]
      Util.assert_responds_to(:resolve, address_resolver) { ":address_resolution_policy must respond to :resolve, #{address_resolver.inspect} but doesn't" }
    end

    def parse_synchronize_schema
      return {} unless options.has_key?(:synchronize_schema)
      {synchronize_schema: !!options[:synchronize_schema]}
    end

    def gather_hosts
      Array(options.fetch(:hosts, '127.0.0.1')).map do |host|
        case host
        when ::IPAddr
          host
        when ::String # ip address or hostname
          Resolv.each_address(host) { |ip| ::IPAddr.new(ip) }
        else
          raise ::ArgumentError, ":hosts must be String or IPAddr, #{host.inspect} given"
        end
      end.flatten.tap do |hosts|
        raise ::ArgumentError, ":hosts #{options[:hosts].inspect} could not be resolved to any ip address" if hosts.empty?
      end.shuffle
    end

  end
end
