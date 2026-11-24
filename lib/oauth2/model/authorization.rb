module OAuth2
  module Model

    class Authorization
      include Mongoid::Document

      MAX_ACCESS_TOKENS = 10

      field :client_id,                   :type => String
      field :scope,                       :type => String
      field :code,                        :type => String
      field :access_token_hash,           :type => String
      # Hashes of the live access tokens, oldest-minted first. Written only by
      # the atomic updates in append_access_token and generate_access_token.
      field :access_token_hashes,         :type => Array
      field :refresh_token_hash,          :type => String
      field :expires_at,                  :type => Time

      belongs_to :oauth2_resource_owner, :polymorphic => true
      alias :owner  :oauth2_resource_owner
      alias :owner= :oauth2_resource_owner=

      belongs_to :client, :class_name => 'OAuth2::Model::Client'

      validates_presence_of :client, :owner

      validates_uniqueness_of :code,               :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :refresh_token_hash, :scope => :client_id, :allow_nil => true
      validates_uniqueness_of :access_token_hash,                        :allow_nil => true

      extend Hashing
      hashes_attributes :access_token, :refresh_token

      def self.for(resource_owner, client)
        return nil unless resource_owner and client
        resource_owner.oauth2_authorizations.where({ :client_id => client.id }).first
      end

      def self.create_code(client)
        OAuth2.generate_id do |code|
          client.authorizations.where({:code => code}).count.zero?
        end
      end

      def self.create_access_token
        OAuth2.generate_id do |token|
          hash = OAuth2.hashify(token)
          self.or({:access_token_hash => hash}, {:access_token_hashes => hash}).count.zero?
        end
      end

      def self.create_refresh_token(client)
        OAuth2.generate_id do |refresh_token|
          hash = OAuth2.hashify(refresh_token)
          client.authorizations.where({:refresh_token_hash => hash}).count.zero?
        end
      end

      def self.for_response_type(response_type, attributes = {})
        instance = self.for(attributes[:owner], attributes[:client]) || self.new
        instance.owner  = attributes[:owner]
        instance.client = attributes[:client]
        mints_token = false
        case response_type
          when CODE
            instance.code ||= create_code(attributes[:client])
          when TOKEN
            mints_token = true
            instance.refresh_token ||= create_refresh_token(attributes[:client])
          when CODE_AND_TOKEN
            instance.code = create_code(attributes[:client])
            mints_token = true
            instance.refresh_token ||= create_refresh_token(attributes[:client])
        end

        if attributes[:duration]
          instance.expires_at = Time.now + attributes[:duration].to_i
        else
          instance.expires_at = nil
        end

        if attributes[:scope]
          scopes = instance.scopes + attributes[:scope].split(/\s+/)
          instance.scope = scopes.entries.join(' ')
        end
        instance.owner.oauth2_authorizations += [instance]
        instance.owner.save
        return false unless instance.save
        instance.append_access_token if mints_token && attributes.fetch(:mint_access_token, true)
        instance
      end

      def exchange!
        self.code          = nil
        self.refresh_token = nil
        save!
        append_access_token
      end

      def expired?
        return false unless expires_at
        expires_at < Time.now
      end

      def expires_in
        expires_at && (expires_at - Time.now).ceil
      end

      def generate_code
        self.code ||= self.class.create_code(client)
        save && code
      end

      # Adds a token alongside the live ones, dropping the oldest past the cap.
      # A hash still in the legacy field moves into the list in the same update.
      # It goes just before the new token: the list is normally empty then, and
      # after a rollback restore the legacy hash is the newest token.
      def append_access_token
        token = self.class.create_access_token
        hash  = OAuth2.hashify(token)
        loop do
          legacy = current_legacy_hash
          update = { '$push' => { 'access_token_hashes' => {
            '$each' => [legacy, hash].compact, '$slice' => -MAX_ACCESS_TOKENS } } }
          update['$unset'] = { 'access_token_hash' => '' } if legacy
          # Conditional on the legacy value, so concurrent grants can't fold it twice
          result = self.class.collection.update_one({ '_id' => id, 'access_token_hash' => legacy }, update)
          return @access_token = token if result.n == 1
        end
      end

      # Replaces every live token with a new one.
      def generate_access_token
        return access_token if access_token
        return false unless save
        token  = self.class.create_access_token
        result = self.class.collection.update_one({ '_id' => id }, {
          '$set'   => { 'access_token_hashes' => [OAuth2.hashify(token)] },
          '$unset' => { 'access_token_hash' => '' } })
        raise Mongoid::Errors::DocumentNotFound.new(self.class, id) if result.n.zero?
        @access_token = token
      end

      def grants_access?(user, *scopes)
        not expired? and user == owner and in_scope?(scopes)
      end

      def in_scope?(request_scope)
        [*request_scope].all?(&scopes.method(:include?))
      end

      def scopes
        scopes = scope ? scope.split(/\s+/) : []
        Set.new(scopes)
      end

    private

      def current_legacy_hash
        doc = self.class.collection.find('_id' => id).projection('access_token_hash' => 1).first
        raise Mongoid::Errors::DocumentNotFound.new(self.class, id) unless doc
        doc['access_token_hash']
      end
    end

  end
end

