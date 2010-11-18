module OAuth2
  module Model
    
    class AccessCode < ActiveRecord::Base
      set_table_name :oauth2_access_codes
      belongs_to :client, :class_name => 'OAuth2::Model::Client'
    end
    
  end
end

