# encoding: utf-8

require 'spec_helper'
require 'cql/connection'


describe 'Startup' do
  let :connection do
    Cql::Connection.open(host: 'localhost', port: 9042)
  end

  after do
    connection.close
  end

  context 'when setting up' do
    it 'sends OPTIONS and receives SUPPORTED' do
      response = connection.execute(Cql::OptionsRequest.new)
      response.options.should include('CQL_VERSION' => ['3.0.0'])
    end

    it 'sends STARTUP and receives READY' do
      response = connection.execute(Cql::StartupRequest.new)
      response.should be_a(Cql::ReadyResponse)
    end

    it 'sends a bad STARTUP and receives ERROR' do
      response = connection.execute(Cql::StartupRequest.new('9.9.9'))
      response.code.should == 10
      response.message.should include('not supported')
    end
  end

  context 'when set up' do
    before do
      response = connection.execute(Cql::StartupRequest.new)
      response
    end

    it 'sends a REGISTER request and receives READY' do
      response = connection.execute(Cql::RegisterRequest.new('TOPOLOGY_CHANGE', 'STATUS_CHANGE', 'SCHEMA_CHANGE'))
      response.should be_a(Cql::ReadyResponse)
    end

    context 'when running queries' do
      let :keyspace_name do
        "cql_rb_#{rand(1000)}"
      end

      def query(cql, consistency=:any)
        response = connection.execute(Cql::QueryRequest.new(cql, consistency))
        raise response.to_s if response.is_a?(Cql::ErrorResponse)
        response
      end

      def create_keyspace!
        query("CREATE KEYSPACE #{keyspace_name} WITH REPLICATION = {'CLASS': 'SimpleStrategy', 'replication_factor': 1}")
      end

      def use_keyspace!
        query("USE #{keyspace_name}")
      end

      def drop_keyspace!
        query("DROP KEYSPACE #{keyspace_name}")
      end

      def create_table!
        query('CREATE TABLE users (user_name VARCHAR, password VARCHAR, email VARCHAR, PRIMARY KEY (user_name))')
      end

      def in_keyspace
        create_keyspace!
        use_keyspace!
        begin
          yield
        ensure
          drop_keyspace!
        end
      end

      def in_keyspace_with_table
        in_keyspace do
          create_table!
          yield
        end
      end

      context 'with QUERY requests' do
        it 'sends a USE command' do
          response = query('USE system', :one)
          response.keyspace.should == 'system'
        end

        it 'sends a bad CQL string and receives ERROR' do
          response = connection.execute(Cql::QueryRequest.new('HELLO WORLD', :any))
          response.should be_a(Cql::ErrorResponse)
        end

        it 'sends a CREATE KEYSPACE command' do
          response = query("CREATE KEYSPACE #{keyspace_name} WITH REPLICATION = {'CLASS': 'SimpleStrategy', 'replication_factor': 1}")
          begin
            response.change.should == 'CREATED'
            response.keyspace.should == keyspace_name
          ensure
            drop_keyspace!
          end
        end

        it 'sends a DROP KEYSPACE command' do
          create_keyspace!
          use_keyspace!
          response = query("DROP KEYSPACE #{keyspace_name}")
          response.change.should == 'DROPPED'
          response.keyspace.should == keyspace_name
        end

        it 'sends an ALTER KEYSPACE command' do
          create_keyspace!
          begin
            response = query("ALTER KEYSPACE #{keyspace_name} WITH DURABLE_WRITES = false")
            response.change.should == 'UPDATED'
            response.keyspace.should == keyspace_name
          ensure
            drop_keyspace!
          end
        end

        it 'sends a CREATE TABLE command' do
          in_keyspace do
            response = query('CREATE TABLE users (user_name VARCHAR, password VARCHAR, email VARCHAR, PRIMARY KEY (user_name))')
            response.change.should == 'CREATED'
            response.keyspace.should == keyspace_name
            response.table.should == 'users'
          end
        end

        it 'sends a DROP TABLE command' do
          in_keyspace_with_table do
            response = query('DROP TABLE users')
            response.change.should == 'DROPPED'
            response.keyspace.should == keyspace_name
            response.table.should == 'users'
          end
        end

        it 'sends an ALTER TABLE command' do
          in_keyspace_with_table do
            response = query('ALTER TABLE users ADD age INT')
            response.change.should == 'UPDATED'
            response.keyspace.should == keyspace_name
            response.table.should == 'users'
          end
        end

        it 'sends an INSERT command' do
          in_keyspace_with_table do
            query(%<INSERT INTO users (user_name, email) VALUES ('phil', 'phil@heck.com')>)
          end
        end

        it 'sends an UPDATE command' do
          in_keyspace_with_table do
            query(%<INSERT INTO users (user_name, email) VALUES ('phil', 'phil@heck.com')>)
            query(%<UPDATE users SET email = 'sue@heck.com' WHERE user_name = 'phil'>)
          end
        end

        it 'sends a DELETE command' do
          in_keyspace_with_table do
            query(%<DELETE email FROM users WHERE user_name = 'sue'>)
          end
        end

        it 'sends a TRUNCATE command' do
          pending 'this blocks indefinitely (but it\'s the same thing in cqlsh)'
          # in_keyspace_with_table do
          #   query(%<TRUNCATE users>)
          # end
        end

        it 'sends a SELECT command' do
          in_keyspace_with_table do
            query(%<INSERT INTO users (user_name, email) VALUES ('phil', 'phil@heck.com')>)
            query(%<INSERT INTO users (user_name, email) VALUES ('sue', 'sue@inter.net')>)
            response = query(%<SELECT * FROM users>, :quorum)
            response.rows.should == [
              {'user_name' => 'phil', 'email' => 'phil@heck.com', 'password' => nil},
              {'user_name' => 'sue',  'email' => 'sue@inter.net', 'password' => nil}
            ]
          end
        end
      end

      context 'with PREPARE requests' do
        it 'sends a PREPARE request and receives RESULT' do
          in_keyspace_with_table do
            response = connection.execute(Cql::PrepareRequest.new('SELECT * FROM users WHERE user_name = ?'))
            response.id.should_not be_nil
            response.metadata.should_not be_nil
          end
        end
      end
    end
  end
end