require 'digest/sha2'

module Ardes #:nodoc:
  module AuthenticatedSystem
    # include this into your ActiveRecord User class
    module Base
      def self.included(base)
        base.class_eval do
          # how long to remember
          cattr_accessor :remember_me_expiry_time
          self.remember_me_expiry_time = 2.weeks
          
          # Virtual attribute for the unencrypted password, and current_password
          attr_accessor :password, :current_password
          attr_reader :original_email
          attr_writer :current_password_required

          validates_presence_of     :email
          validates_presence_of     :password,                   :if => :password_required?
          validates_presence_of     :password_confirmation,      :if => :password_required?
          validates_length_of       :password, :within => 4..40, :if => :password_required?
          validates_confirmation_of :password,                   :if => :password_required?
          validates_format_of :email, :allow_nil => true, :with => RFC822::EmailAddress
          validates_uniqueness_of   :email, :case_sensitive => false
        
          validate_on_update        :validate_current_password
        
          before_save :encrypt_password
          before_create :make_activation_code
          before_create :make_recognition_token

          attr_protected :remember_token, :recognition_token, :crypted_password, :salt, :activation_code, :remember_token_expires_at, :activated_at, :current_password_required
        
          # Authenticates a user by their email and unencrypted password.  Returns the user or nil.
          def self.authenticate(email, password)
            u = find :first, :conditions => ['email = ? and activated_at IS NOT NULL', email] # need to get the salt
            u && u.authenticated?(password) ? u : nil
          end

          # Encrypts some data with the salt.
          def self.encrypt(password, salt)
            Digest::SHA256.hexdigest("--#{salt}--#{password}--")
          end
        end
      end
    
      def after_find
        @original_email = email
      end
    
      # Activates the user in the database.
      def activate
        @activated = true
        self.activated_at = Time.now.utc
        self.activation_code = nil
        save(false)
      end

      def activated?
        # the existence of an activation code means they have not activated yet
        activation_code.nil?
      end

      # Returns true if the user has just been activated.
      def recently_activated?
        @activated
      end

      # resets the activation code and sets @request_activation
      def request_activation
        @request_activation = true
        self.activated_at = nil
        make_activation_code
        save(false)
      end
    
      # Returns true if the user has just requested activation
      def recently_requested_activation?
        @request_activation
      end
    
      # Setes remember_me cookie for 1 hour and flags self as recenlty requested password
      def request_reset_password
        @request_reset_password = true
        remember_me_for 1.hour
      end
    
      def recently_requested_reset_password?
        @request_reset_password
      end
    
      # Encrypts the password with the user salt
      def encrypt(password)
        self.class.encrypt(password, salt)
      end

      def authenticated?(password)
        crypted_password == encrypt(password)
      end
      
      def remember_token?
        remember_token_expires_at && Time.now.utc < remember_token_expires_at 
      end

      # These create and unset the fields required for remembering users between browser closes
      def remember_me
        remember_me_for remember_me_expiry_time
      end

      def remember_me_for(time)
        remember_me_until time.from_now.utc
      end

      def remember_me_until(time)
        self.remember_token_expires_at = time
        self.remember_token            = encrypt("#{email}--#{remember_token_expires_at}")
        save(false)
      end

      def forget_me
        self.remember_token_expires_at = nil
        self.remember_token            = nil
        save(false)
      end

    protected
      def validate_current_password
        errors.add(:current_password, "is incorrect") if current_password_required? && !authenticated?(current_password)
      end
    
      def encrypt_password
        return if password.blank?
        self.salt = Digest::SHA256.hexdigest("--#{Time.now.to_s}--#{email}--") if new_record?
        self.crypted_password = encrypt(password)
      end

      def set_email_if_changed
        self.email = change_email unless change_email.blank?
      end
    
      def current_password_required?
        @current_password_required = email_changed? || !password.blank? if @current_password_required.nil?
        @current_password_required
      end
    
      def email_changed?
        !original_email.blank? && email.downcase != original_email.downcase
      end
    
      def password_required?
        crypted_password.blank? || !password.blank?
      end

      def make_activation_code
        self.activation_code = make_code
      end
    
      def make_recognition_token
        self.recognition_token = make_code
      end
    
      def make_code
        Digest::SHA256.hexdigest( id.to_s + Time.now.to_s.split(//).sort_by {rand}.join )
      end
    end
  end
end