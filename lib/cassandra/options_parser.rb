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

    def initialize(options={})
      @options = options
    end

    # @return [Array<Hash, Array<Cassandra::Host>>]
    def for_driver
      options = Hash[@options.map{ |k, v| [k.to_sym, v] }].select { |k, _| VALID_OPTION_KEYS.include?(k) }

      has_username = options.has_key?(:username)
      has_password = options.has_key?(:password)
      if has_username || has_password
        if has_username && !has_password
          raise ::ArgumentError, "both :username and :password options must be specified, but only :username given"
        end

        if !has_username && has_password
          raise ::ArgumentError, "both :username and :password options must be specified, but only :password given"
        end

        username = options.delete(:username)
        password = options.delete(:password)

        Util.assert_instance_of(::String, username) { ":username must be a String, #{username.inspect} given" }
        Util.assert_instance_of(::String, password) { ":password must be a String, #{password.inspect} given" }
        Util.assert_not_empty(username) { ":username cannot be empty" }
        Util.assert_not_empty(password) { ":password cannot be empty" }

        options[:credentials]   = {:username => username, :password => password}
        options[:auth_provider] = Auth::Providers::Password.new(username, password)
      end

      if options.has_key?(:credentials)
        credentials = options[:credentials]

        Util.assert_instance_of(::Hash, credentials) { ":credentials must be a hash, #{credentials.inspect} given" }
      end

      if options.has_key?(:auth_provider)
        auth_provider = options[:auth_provider]

        Util.assert_responds_to(:create_authenticator, auth_provider) { ":auth_provider #{auth_provider.inspect} must respond to :create_authenticator, but doesn't" }
      end

      has_client_cert = options.has_key?(:client_cert)
      has_private_key = options.has_key?(:private_key)

      if has_client_cert || has_private_key
        if has_client_cert && !has_private_key
          raise ::ArgumentError, "both :client_cert and :private_key options must be specified, but only :client_cert given"
        end

        if !has_client_cert && has_private_key
          raise ::ArgumentError, "both :client_cert and :private_key options must be specified, but only :private_key given"
        end

        client_cert = ::File.expand_path(options[:client_cert])
        private_key = ::File.expand_path(options[:private_key])

        Util.assert_file_exists(client_cert) { ":client_cert #{client_cert.inspect} doesn't exist" }
        Util.assert_file_exists(private_key) { ":private_key #{private_key.inspect} doesn't exist" }
      end

      has_server_cert = options.has_key?(:server_cert)

      if has_server_cert
        server_cert = ::File.expand_path(options[:server_cert])

        Util.assert_file_exists(server_cert) { ":server_cert #{server_cert.inspect} doesn't exist" }
      end

      if has_client_cert || has_server_cert
        context = ::OpenSSL::SSL::SSLContext.new

        if has_server_cert
          context.ca_file     = server_cert
          context.verify_mode = ::OpenSSL::SSL::VERIFY_PEER
        end

        if has_client_cert
          context.cert = ::OpenSSL::X509::Certificate.new(File.read(client_cert))

          if options.has_key?(:passphrase)
            context.key = ::OpenSSL::PKey::RSA.new(File.read(private_key), options[:passphrase])
          else
            context.key = ::OpenSSL::PKey::RSA.new(File.read(private_key))
          end
        end

        options[:ssl] = context
      end

      if options.has_key?(:ssl)
        ssl = options[:ssl]

        Util.assert_instance_of_one_of([::TrueClass, ::FalseClass, ::OpenSSL::SSL::SSLContext], ssl) { ":ssl must be a boolean or an OpenSSL::SSL::SSLContext, #{ssl.inspect} given" }
      end

      if options.has_key?(:compression)
        compression = options.delete(:compression)

        case compression
        when :snappy
          require 'cassandra/compression/compressors/snappy'
          options[:compressor] = Compression::Compressors::Snappy.new
        when :lz4
          require 'cassandra/compression/compressors/lz4'
          options[:compressor] = Compression::Compressors::Lz4.new
        else
          raise ::ArgumentError, ":compression must be either :snappy or :lz4, #{compression.inspect} given"
        end
      end

      if options.has_key?(:compressor)
        compressor = options[:compressor]
        methods    = [:algorithm, :compress?, :compress, :decompress]

        Util.assert_responds_to_all(methods, compressor) { ":compressor #{compressor.inspect} must respond to #{methods.inspect}, but doesn't" }
      end

      if options.has_key?(:logger)
        logger  = options[:logger]
        methods = [:debug, :info, :warn, :error, :fatal]

        Util.assert_responds_to_all(methods, logger) { ":logger #{logger.inspect} must respond to #{methods.inspect}, but doesn't" }
      end

      if options.has_key?(:port)
        port = options[:port] = Integer(options[:port])

        Util.assert_one_of(0..65536, port) { ":port must be a valid ip port, #{port} given" }
      end

      if options.has_key?(:datacenter)
        options[:datacenter] = String(options[:datacenter])
      end

      [ :connect_timeout, :timeout, :heartbeat_interval, :idle_timeout,
        :schema_refresh_delay, :schema_refresh_timeout
      ].each do |key|
        Util.assert_nil_or_numeric_greater_zero(options[key], key)
      end

      if options.has_key?(:load_balancing_policy)
        load_balancing_policy = options[:load_balancing_policy]
        methods = [:host_up, :host_down, :host_found, :host_lost, :setup, :teardown, :distance, :plan]

        Util.assert_responds_to_all(methods, load_balancing_policy) { ":load_balancing_policy #{load_balancing_policy.inspect} must respond to #{methods.inspect}, but doesn't" }
      end

      if options.has_key?(:reconnection_policy)
        reconnection_policy = options[:reconnection_policy]

        Util.assert_responds_to(:schedule, reconnection_policy) { ":reconnection_policy #{reconnection_policy.inspect} must respond to :schedule, but doesn't" }
      end

      if options.has_key?(:retry_policy)
        retry_policy = options[:retry_policy]
        methods = [:read_timeout, :write_timeout, :unavailable]

        Util.assert_responds_to_all(methods, retry_policy) { ":retry_policy #{retry_policy.inspect} must respond to #{methods.inspect}, but doesn't" }
      end

      if options.has_key?(:listeners)
        options[:listeners] = Array(options[:listeners])
      end

      if options.has_key?(:consistency)
        consistency = options[:consistency]

        Util.assert_one_of(CONSISTENCIES, consistency) { ":consistency must be one of #{CONSISTENCIES.inspect}, #{consistency.inspect} given" }
      end

      if options.has_key?(:trace)
        options[:trace] = !!options[:trace]
      end

      if options.has_key?(:shuffle_replicas)
        options[:shuffle_replicas] = !!options[:shuffle_replicas]
      end

      if options.has_key?(:page_size)
        page_size = options[:page_size]

        unless page_size.nil?
          page_size = options[:page_size] = Integer(page_size)
          Util.assert(page_size > 0) { ":page_size must be a positive integer, #{page_size.inspect} given" }
        end
      end

      if options.has_key?(:futures_factory)
        futures_factory = options[:futures_factory]
        methods = [:error, :value, :promise, :all]

        Util.assert_responds_to_all(methods, futures_factory) { ":futures_factory #{futures_factory.inspect} must respond to #{methods.inspect}, but doesn't" }
      end

      if options.has_key?(:address_resolution)
        address_resolution = options.delete(:address_resolution)

        case address_resolution
        when :none
          # do nothing
        when :ec2_multi_region
          options[:address_resolution_policy] = AddressResolution::Policies::EC2MultiRegion.new
        else
          raise ::ArgumentError, ":address_resolution must be either :none or :ec2_multi_region, #{address_resolution.inspect} given"
        end
      end

      if options.has_key?(:address_resolution_policy)
        address_resolver = options[:address_resolution_policy]

        Util.assert_responds_to(:resolve, address_resolver) { ":address_resolution_policy must respond to :resolve, #{address_resolver.inspect} but doesn't" }
      end

      if options.has_key?(:synchronize_schema)
        options[:synchronize_schema] = !!options[:synchronize_schema]
      end

      hosts = []

      Array(options.fetch(:hosts, '127.0.0.1')).each do |host|
        case host
        when ::IPAddr
          hosts << host
        when ::String # ip address or hostname
          Resolv.each_address(host) do |ip|
            hosts << ::IPAddr.new(ip)
          end
        else
          raise ::ArgumentError, ":hosts must be String or IPAddr, #{host.inspect} given"
        end
      end

      if hosts.empty?
        raise ::ArgumentError, ":hosts #{options[:hosts].inspect} could not be resolved to any ip address"
      end

      hosts.shuffle!

      [options, hosts]
    end

  end
end
