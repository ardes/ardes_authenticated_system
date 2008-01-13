module Ardes#:nodoc:
  module AuthenticatedSystem
    module TableDefinition
      def authenticated_system
        string "email"
        string "remember_token"
        string "recognition_token"
        string  "crypted_password", :limit => 64
        string  "salt",             :limit => 64
        string  "activation_code",  :limit => 64
        datetime "activated_at"
        datetime "remember_token_expires_at"
        timestamps
      end
    end
  end
end